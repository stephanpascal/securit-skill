'use strict';
const { scanText } = require('../lib/patterns');
const { NET_RULES, SUSPICIOUS_DOMAINS_RE } = require('../lib/shell-rules');
const { makeFinding } = require('../lib/finding');
const { extractUrls, hostOf, isInternalHost, shannonEntropy, truncate } = require('../lib/util');

const C = 'code';
const RULES = [
  { id: 'CODE_EVAL', sev: 'high', review: true, re: /(^|[^.\w$])eval\s*\(/, title: 'Exécution dynamique via eval()', desc: 'eval exécute une chaîne comme du code : vecteur classique de charge masquée.', fix: 'Supprimer eval et utiliser JSON.parse ou une logique explicite.' },
  { id: 'CODE_NEW_FUNCTION', sev: 'high', review: true, re: /new\s+Function\s*\(/, title: 'Construction de code via new Function()', desc: 'Équivalent à eval : exécute du code construit dynamiquement.', fix: 'Remplacer par du code statique.' },
  { id: 'CODE_TIMER_STRING', sev: 'medium', review: true, re: /\bset(Timeout|Interval)\s*\(\s*['"`]/, title: 'setTimeout/setInterval avec une chaîne', desc: 'Une chaîne passée à un timer est évaluée comme du code.', fix: 'Passer une fonction.' },
  { id: 'CODE_CHILD_PROCESS', sev: 'high', sevByType: { fe: 'critical' }, review: true, re: /require\s*\(\s*['"`](node:)?child_process['"`]\s*\)|from\s+['"`](node:)?child_process['"`]|import\s*\(\s*['"`](node:)?child_process/, title: 'Exécution de commandes système (child_process)', desc: 'Permet d\'exécuter des commandes du système. Inattendu dans un frontend, à justifier dans un BFF.', fix: 'Vérifier chaque appel exec/spawn et la provenance des arguments.' },
  { id: 'CODE_EXEC_ENTREE_UTILISATEUR', sev: 'critical', re: /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync|eval|Function|runInNewContext|runInThisContext)\s*\([^)]*\breq\.(query|body|params|headers|cookies)/, title: 'Exécution de commande/code à partir d\'une entrée HTTP', desc: 'Une donnée de requête HTTP est passée à une fonction d\'exécution : backdoor ou injection de commande (RCE).', fix: 'Supprimer immédiatement ; ne jamais exécuter une entrée utilisateur.' },
  { id: 'CODE_VM', sev: 'high', review: true, re: /require\s*\(\s*['"`](node:)?vm['"`]\s*\)|from\s+['"`](node:)?vm['"`]|\brunIn(New|This)Context\s*\(/, title: 'Exécution de code via le module vm', desc: 'Le module vm exécute du code arbitraire (ce n\'est pas un bac à sable de sécurité).', fix: 'Vérifier la provenance du code exécuté.' },
  { id: 'CODE_REQUIRE_DYNAMIQUE', sev: 'medium', review: true, re: /\brequire\s*\(\s*(?!['"`])[A-Za-z_$][\w$.]*\s*[+)]/, exclude: /require\s*\(\s*(require|path)\.resolve|require\.resolve/, title: 'require() dynamique', desc: 'Le module chargé est calculé à l\'exécution : peut charger un fichier caché ou téléchargé.', fix: 'Utiliser des imports statiques.' },
  { id: 'CODE_OBFUSCATEUR', sev: 'critical', re: /\b_0x[0-9a-f]{4,6}\b/i, title: 'Code obfusqué (signature javascript-obfuscator)', desc: 'Les identifiants _0x… sont la signature d\'un outil d\'obfuscation : aucun code source légitime n\'est écrit ainsi.', fix: 'Identifier l\'origine du fichier, le désobfusquer pour analyse et le supprimer.' },
  { id: 'CODE_ECHAPPEMENTS_HEX', sev: 'high', review: true, re: /(\\x[0-9a-fA-F]{2}){15,}|(\\u[0-9a-fA-F]{4}){12,}/, title: 'Longue chaîne d\'échappements hexadécimaux/unicode', desc: 'Technique de masquage d\'une chaîne (URL, commande) aux relectures.', fix: 'Décoder la chaîne pour vérifier son contenu.' },
  { id: 'CODE_FROMCHARCODE', sev: 'high', review: true, re: /String\.fromCharCode\s*\(\s*(\d+\s*,\s*){8,}/, title: 'Chaîne reconstruite via String.fromCharCode', desc: 'Technique de masquage d\'une chaîne.', fix: 'Décoder la chaîne pour vérifier son contenu.' },
  { id: 'CODE_BASE64_LONG', sev: 'high', review: true, re: /(atob|Buffer\.from)\s*\(\s*['"`][A-Za-z0-9+\/=]{120,}/, title: 'Décodage d\'un long contenu base64', desc: 'Un long bloc base64 décodé à l\'exécution peut contenir une charge malveillante.', fix: 'Décoder pour vérifier le contenu.' },
  { id: 'CODE_SENDBEACON', sev: 'medium', review: true, re: /navigator\.sendBeacon\s*\(/, title: 'Envoi silencieux de données (sendBeacon)', desc: 'sendBeacon envoie des données même à la fermeture de la page : utilisé par les traqueurs et les skimmers.', fix: 'Vérifier la destination et les données envoyées.' },
  { id: 'CODE_INJECTION_SCRIPT', sev: 'high', review: true, re: /createElement\s*\(\s*['"`]script['"`]\s*\)|document\.write(ln)?\s*\(|insertAdjacentHTML\s*\([^)]*<script/i, title: 'Injection dynamique de script dans la page', desc: 'Ajout dynamique d\'un script : technique de chargement d\'un code tiers non relu (skimmer, traqueur).', fix: 'Vérifier l\'URL du script chargé ; préférer une dépendance versionnée.' },
  { id: 'CODE_ANGULAR_BYPASS', sev: 'medium', review: true, re: /bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)\s*\(/, title: 'Contournement de la protection XSS d\'Angular', desc: 'bypassSecurityTrust* désactive l\'assainissement d\'Angular pour la valeur concernée.', fix: 'Vérifier que la valeur ne provient jamais d\'une source non maîtrisée.' },
  { id: 'CODE_INNERHTML', sev: 'low', re: /\.(inner|outer)HTML\s*=(?!=)|\[innerHTML\]\s*=/, title: 'Affectation innerHTML', desc: 'Risque d\'injection HTML/XSS si la valeur n\'est pas maîtrisée.', fix: 'Utiliser textContent ou l\'interpolation Angular.' },
  { id: 'CODE_TLS_DESACTIVE', sev: 'high', re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|strictSSL\s*:\s*false|checkServerIdentity\s*:\s*\(\)\s*=>/, title: 'Vérification des certificats TLS désactivée', desc: 'Permet l\'interception des échanges (man-in-the-middle).', fix: 'Réactiver la vérification et configurer le certificat d\'entreprise (NODE_EXTRA_CA_CERTS).' },
  { id: 'CODE_DUMP_ENV', sev: 'high', review: true, re: /JSON\.stringify\s*\(\s*process\.env\s*\)|Object\.(keys|entries|values)\s*\(\s*process\.env\s*\)/, title: 'Lecture de toutes les variables d\'environnement', desc: 'Collecte de l\'ensemble des variables d\'environnement (tokens, secrets) : typique d\'une exfiltration.', fix: 'Ne lire que les variables nécessaires, nommément.' },
  { id: 'CODE_FICHIERS_SENSIBLES', sev: 'high', review: true, re: /(\.ssh[\/\\]|\bid_rsa\b|\bid_ed25519\b|\.npmrc\b|\.aws[\/\\]credentials|\/etc\/(passwd|shadow)\b|\.kube[\/\\]config|\.docker[\/\\]config\.json|\.git-credentials|\.bash_history|Login Data|wallet\.dat)/, exclude: /^\s*(\/\/|\*|#)/, title: 'Accès à des fichiers d\'identifiants', desc: 'Lecture de clés SSH, tokens npm, identifiants cloud ou de navigateur : comportement de voleur d\'identifiants.', fix: 'Supprimer et investiguer.' },
  { id: 'CODE_EMPREINTE_MACHINE', sev: 'low', review: true, re: /\bos\.(hostname|userInfo|networkInterfaces|homedir)\s*\(/, title: 'Collecte d\'informations sur la machine', desc: 'Nom de machine, utilisateur, interfaces réseau : souvent collectés par les malwares avant exfiltration.', fix: 'Vérifier l\'usage ; signalé plus fortement si combiné à un envoi réseau.' },
  { id: 'CODE_SERVEUR_RESEAU', sev: 'medium', sevByType: { fe: 'high' }, review: true, re: /\b(net|tls|dgram)\.create(Server|Socket)\s*\(/, title: 'Ouverture d\'un serveur/socket réseau bas niveau', desc: 'Un serveur TCP/UDP brut peut constituer une backdoor parallèle au serveur HTTP.', fix: 'Vérifier le besoin et le port utilisé.' },
  { id: 'CODE_SOCKET_SORTANTE', sev: 'high', review: true, re: /\bnet\.(connect|createConnection)\s*\(|new\s+net\.Socket\s*\(/, title: 'Connexion TCP sortante brute', desc: 'Connexion TCP directe : utilisée par les reverse shells.', fix: 'Vérifier la destination.' },
  { id: 'CODE_BOMBE_LOGIQUE', sev: 'medium', review: true, re: /(Date\.now\(\)|new\s+Date\(\)(\.getTime\(\))?)\s*[<>]=?\s*(\d{12,}|new\s+Date\(\s*['"`]20\d\d)/, title: 'Condition sur une date codée en dur', desc: 'Un comportement déclenché à partir d\'une date peut être une bombe logique.', fix: 'Vérifier ce qui est déclenché après cette date.' },
  { id: 'CODE_ROUTE_SUSPECTE', sev: 'medium', review: true, re: /\.(get|post|put|all|use)\s*\(\s*['"`]\/?(debug|backdoor|shell|exec|cmd|eval|console|run|_internal|hidden|cmdexec|system)\b/i, title: 'Route HTTP au nom suspect', desc: 'Route de type /shell, /exec, /debug : point d\'entrée possible d\'une backdoor.', fix: 'Vérifier son rôle et sa protection.' },
  { id: 'CODE_CORS_OUVERT', sev: 'medium', review: true, re: /Access-Control-Allow-Origin['"`]?\s*[,:]\s*['"`]\*|\borigin\s*:\s*(['"`]\*['"`]|true)\s*[,}]/, title: 'CORS ouvert à toutes les origines', desc: 'N\'importe quel site peut appeler l\'API depuis le navigateur d\'un utilisateur.', fix: 'Restreindre aux origines connues.' },
  { id: 'CODE_EXFIL_DNS', sev: 'high', review: true, re: /\bdns\.(resolve\w*|lookup)\s*\(\s*`[^`]*\$\{/, title: 'Requête DNS construite avec des données', desc: 'Technique d\'exfiltration par DNS.', fix: 'Vérifier les données intégrées au nom résolu.' },
  { id: 'CODE_PROCESS_BINDING', sev: 'high', review: true, re: /process\.binding\s*\(|process\.dlopen\s*\(/, title: 'Accès aux API internes de Node (binding / dlopen)', desc: 'Chargement de code natif ou accès bas niveau.', fix: 'Vérifier la justification.' },
  { id: 'CODE_DETOURNEMENT_GLOBAL', sev: 'high', review: true, re: /XMLHttpRequest\.prototype\.(open|send|setRequestHeader)\s*=|\b(window|globalThis|self)\.fetch\s*=(?!=)|HTMLFormElement\.prototype\.submit\s*=/, title: 'Détournement de fetch / XMLHttpRequest / formulaires', desc: 'Remplacer les fonctions réseau globales permet d\'intercepter toutes les requêtes (technique des skimmers type Magecart).', fix: 'Supprimer sauf intercepteur officiel documenté.' },
  { id: 'CODE_SKIMMER_FORMULAIRE', sev: 'medium', review: true, re: /querySelector(All)?\s*\(\s*['"`][^'"`]*(type=['"]?password|cvv|cc-number|card-?number|iban)/i, title: 'Sélection de champs sensibles (mot de passe, carte)', desc: 'Lecture programmatique de champs sensibles : à vérifier si combiné à un envoi réseau.', fix: 'Vérifier l\'usage.' },
  { id: 'CODE_WASM', sev: 'low', review: true, re: /WebAssembly\.(instantiate|compile)(Streaming)?\s*\(/, title: 'Chargement de WebAssembly', desc: 'Du code binaire opaque est exécuté (utilisé notamment par les mineurs navigateur).', fix: 'Vérifier l\'origine du module wasm.' },
  { id: 'CODE_PROPAGATION_NPM', sev: 'high', review: true, re: /['"`][^'"`\n]*\bnpm\s+(publish|whoami|token\s+create|owner\s+add|adduser|login)\b|registry\.npmjs\.org\/-\/(whoami|npm\/v1\/tokens|user\/)/, title: 'Code applicatif qui publie sur npm ou manipule les tokens npm', desc: 'Comportement de ver (Shai-Hulud, 2025) : le code vole le token npm du poste puis republie des paquets piégés au nom de la victime.', fix: 'Aucun code applicatif ne doit appeler npm publish ou interroger les tokens npm : investiguer.' },
  { id: 'CODE_API_GITHUB_ECRITURE', sev: 'high', review: true, re: /api\.github\.com\/(user\/repos|repos\/[^'"`\s]+\/(actions\/(secrets|workflows)|contents|hooks))|\/user\/repos['"`]|['"`]\/repos\/[^'"`]*\/actions\/secrets/, title: 'Écriture via l\'API GitHub (création de dépôt, secrets, workflows)', desc: 'Shai-Hulud et s1ngularity créaient des dépôts publics pour y déposer les secrets volés, et injectaient des workflows.', fix: 'Vérifier pourquoi ce code écrit sur GitHub.' },
  { id: 'CODE_SCANNER_SECRETS_EMBARQUE', sev: 'high', review: true, re: /\btrufflehog\b|\bgitleaks\s+(detect|dir|git)\b|github\.com\/trufflesecurity/i, title: 'Outil de recherche de secrets lancé depuis le code', desc: 'Shai-Hulud téléchargeait trufflehog pour récolter les secrets du poste et de la CI.', fix: 'Un outil de recherche de secrets n\'a rien à faire dans le code applicatif.' },
  ...NET_RULES,
].map(r => Object.assign({ cat: C }, r));

// Règles à fort signal appliquées aussi aux fichiers minifiés
const MINIFIED_RULE_IDS = new Set(['CODE_OBFUSCATEUR', 'CODE_CHILD_PROCESS', 'CODE_EXEC_ENTREE_UTILISATEUR', 'CODE_DUMP_ENV', 'CODE_FICHIERS_SENSIBLES', 'NET_SUSPICIOUS_DOMAIN', 'NET_CRYPTO_MINER', 'NET_CLOUD_METADATA', 'CODE_DETOURNEMENT_GLOBAL', 'NET_DETOURNEMENT_AGENT_IA', 'NET_C2_BLOCKCHAIN', 'CODE_PROPAGATION_NPM', 'CODE_API_GITHUB_ECRITURE', 'CODE_SCANNER_SECRETS_EMBARQUE']);
const MINIFIED_RULES = RULES.filter(r => MINIFIED_RULE_IDS.has(r.id));

const R = {
  BIDI: { id: 'CODE_UNICODE_BIDI', sev: 'critical', cat: C, title: 'Caractères de contrôle bidirectionnels (Trojan Source)', desc: 'Ces caractères invisibles font afficher le code différemment de ce qui est exécuté (CVE-2021-42574).', fix: 'Supprimer ces caractères ; examiner le code en hexadécimal.' },
  ZW: { id: 'CODE_UNICODE_INVISIBLE', sev: 'high', cat: C, review: true, title: 'Caractères invisibles dans le code', desc: 'Les caractères de largeur nulle peuvent masquer un identifiant ou une chaîne différente de celle affichée.', fix: 'Supprimer ces caractères.' },
  HOMO: { id: 'CODE_HOMOGLYPHE', sev: 'medium', cat: C, review: true, title: 'Mélange de lettres latines et cyrilliques/grecques dans un même mot', desc: 'Les homoglyphes permettent de créer un identifiant visuellement identique à un autre.', fix: 'Vérifier le mot concerné.' },
  LONG: { id: 'CODE_LIGNE_TRES_LONGUE', sev: 'medium', cat: C, review: true, title: 'Ligne anormalement longue dans un fichier source', desc: 'Du code peut être caché en fin de ligne très longue, hors de l\'écran lors des relectures.', fix: 'Afficher la ligne entière et vérifier sa fin.' },
  ENTROPY: { id: 'CODE_CHAINE_HAUTE_ENTROPIE', sev: 'medium', cat: C, review: true, title: 'Longue chaîne à forte entropie (contenu chiffré ou encodé)', desc: 'Une chaîne longue et aléatoire peut contenir une charge chiffrée ou encodée.', fix: 'Identifier ce que contient la chaîne.' },
  EXFIL: { id: 'CODE_EXFILTRATION', sev: 'high', cat: C, review: true, title: 'Collecte de données sensibles ET envoi vers un domaine externe dans le même fichier', desc: 'Le fichier lit des données sensibles et contient un appel réseau vers un hôte externe : schéma typique d\'exfiltration.', fix: 'Vérifier précisément quelles données partent vers quel hôte.' },
  KEYLOG: { id: 'CODE_KEYLOGGER', sev: 'high', cat: C, review: true, title: 'Écoute du clavier combinée à un envoi réseau', desc: 'Capture des frappes clavier et envoi réseau dans le même fichier : schéma de keylogger.', fix: 'Vérifier les données envoyées.' },
  EXT_SCRIPT: { id: 'CODE_SCRIPT_EXTERNE_HTML', sev: 'medium', cat: C, review: true, title: 'Script externe chargé dans une page HTML', desc: 'Un script tiers chargé à l\'exécution peut être modifié à tout moment par son hébergeur.', fix: 'Héberger le script localement ou ajouter integrity="sha384-…" et crossorigin.' },
  NG_SCRIPTS: { id: 'ANGULAR_SCRIPT_GLOBAL', sev: 'medium', cat: C, review: true, title: 'Script global injecté via angular.json', desc: 'Les "scripts" d\'angular.json sont injectés dans toutes les pages sans passer par les imports du code.', fix: 'Vérifier chaque script listé.' },
  NG_SCRIPT_URL: { id: 'ANGULAR_SCRIPT_DISTANT', sev: 'high', cat: C, title: 'angular.json référence un script distant ou hors projet', desc: 'Un script global distant ou hors du dépôt échappe à la relecture.', fix: 'Supprimer ou rapatrier le script dans node_modules/ via une dépendance versionnée.' },
  PROXY_EXT: { id: 'ANGULAR_PROXY_EXTERNE', sev: 'medium', cat: C, review: true, title: 'Proxy de développement vers un hôte externe', desc: 'Le proxy de dev redirige des appels vers un hôte externe (poste développeur).', fix: 'Vérifier la cible.' },
  PORT: { id: 'CODE_PORT_ECOUTE_INATTENDU', sev: 'medium', cat: C, review: true, title: 'Serveur en écoute sur un port inhabituel', desc: 'Un port codé en dur et inhabituel peut correspondre à un service caché.', fix: 'Vérifier le service exposé sur ce port.' },
  MULTI_LISTEN: { id: 'CODE_ECOUTES_MULTIPLES', sev: 'medium', cat: C, review: true, title: 'Plusieurs serveurs en écoute dans l\'application', desc: 'Plusieurs appels .listen() : un serveur secondaire peut servir de backdoor.', fix: 'Vérifier le rôle de chaque serveur.' },
  NG_SOURCEMAP: { id: 'ANGULAR_SOURCEMAP_PRODUCTION', sev: 'medium', cat: C, title: 'Source maps activées en production', desc: 'Le code source complet (commentaires, logique, URL internes) est publié avec l\'application.', fix: 'sourceMap: false dans la configuration production (ou "hidden": true pour un outil de suivi d\'erreurs).' },
  NG_CSP: { id: 'ANGULAR_CSP_ABSENTE', sev: 'low', cat: C, title: 'Aucune Content-Security-Policy', desc: 'Sans CSP, un script injecté (XSS, dépendance compromise, extension) peut charger du code et exfiltrer des données vers n\'importe quel domaine.', fix: 'Définir une CSP (en-tête nginx ou meta dans index.html) limitant script-src et connect-src.' },
  NGSW_EXT: { id: 'ANGULAR_SERVICE_WORKER_EXTERNE', sev: 'low', cat: C, review: true, title: 'Service worker mettant en cache une ressource externe', desc: 'Une ressource tierce mise en cache par le service worker reste servie aux utilisateurs même après sa correction côté serveur.', fix: 'Vérifier la légitimité de l\'URL.' },
};

const CODE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx', '.vue', '.svelte']);
const HTML_EXT = new Set(['.html', '.htm']);
const BENIGN_HOSTS = /(^|\.)(w3\.org|angular\.(io|dev)|github\.com|githubusercontent\.com|npmjs\.(com|org)|schema\.org|json-schema\.org|example\.(com|org)|mozilla\.org|apache\.org|opensource\.org|nodejs\.org|typescriptlang\.org|microsoft\.com|google\.com|googleapis\.com|gstatic\.com|stackoverflow\.com|rxjs\.dev|reactivex\.io|jestjs\.io|karma-runner\.github\.io|creativecommons\.org|xmlsoap\.org|purl\.org|ogp\.me|unpkg\.com|jsdelivr\.net|cdnjs\.cloudflare\.com|eslint\.org|prettier\.io|nestjs\.com|expressjs\.com|helm\.sh|kubernetes\.io|docker\.com)$/;

const STRONG_SOURCES = /document\.cookie|JSON\.stringify\s*\(\s*process\.env|Object\.(keys|entries)\s*\(\s*process\.env|\.ssh[\/\\]|id_rsa|\.npmrc|os\.(hostname|userInfo|networkInterfaces)\s*\(|type=['"]?password/;
const KEY_SOURCES = /addEventListener\s*\(\s*['"`]key(down|up|press)['"`]|onkey(down|up|press)\s*=/;
const SINKS = /\bfetch\s*\(|XMLHttpRequest|sendBeacon|new\s+Image\s*\(\s*\)|\.src\s*=|\baxios\b|https?\.request\s*\(|https?\.get\s*\(|new\s+WebSocket|\$\.(ajax|post|get)\b|\.post\s*\(/;

function lineOf(text, idx) { return text.slice(0, idx).split('\n').length; }

module.exports = {
  id: 'source-code',
  label: 'Code source',
  category: C,
  controls: [
    'Exécution dynamique : eval, new Function, vm, require dynamique, child_process (critique dans un frontend)',
    'Exécution de commande à partir d\'une entrée HTTP (RCE / backdoor)',
    'Obfuscation : identifiants _0x, échappements hex, fromCharCode, base64 long, lignes très longues, chaînes à forte entropie',
    'Caractères invisibles, bidirectionnels (Trojan Source) et homoglyphes',
    'Exfiltration : cookies, variables d\'environnement, fichiers d\'identifiants, empreinte machine + envoi réseau externe',
    'Keyloggers, skimmers de formulaires, détournement de fetch/XHR, injection de scripts',
    'Angular : bypassSecurityTrust*, scripts globaux d\'angular.json, proxy de dev, scripts externes dans index.html',
    'BFF : serveurs réseau bruts, ports d\'écoute inhabituels, écoutes multiples, routes suspectes, CORS, TLS désactivé',
    'Domaines suspects, IP publiques, métadonnées cloud, mineurs de cryptomonnaie, bombes logiques',
    'Inventaire des domaines externes contactés',
  ],
  async run(ctx) {
    const findings = [];
    const domains = new Map();
    const listens = [];
    let count = 0;
    const internal = ctx.config.domaines.internes || [];

    for (const file of ctx.files) {
      const isCode = CODE_EXT.has(file.ext) && !/\.d\.ts$/.test(file.base);
      const isHtml = HTML_EXT.has(file.ext);
      if (!isCode && !isHtml) continue;
      const text = ctx.readText(file);
      if (!text) continue;
      count++;
      const lines = text.split(/\r?\n/);
      const avgLen = text.length / Math.max(1, lines.length);
      const minified = /\.min\.(js|mjs|cjs)$/.test(file.base) || avgLen > 400;
      const opts = { file: file.rel, category: C, projectType: ctx.projectType };
      findings.push(...scanText(text, minified ? MINIFIED_RULES : RULES, opts));

      // Unicode
      if (isCode) {
        const bidi = /[‪-‮⁦-⁩]/.exec(text);
        if (bidi) findings.push(makeFinding(R.BIDI, { file: file.rel, line: lineOf(text, bidi.index), evidence: 'U+' + bidi[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + ' : ' + truncate(lines[lineOf(text, bidi.index) - 1], 120) }));
        const zw = /[​-‍⁠᠎]|(?!^)﻿/.exec(text.slice(1));
        if (zw) findings.push(makeFinding(R.ZW, { file: file.rel, line: lineOf(text, zw.index + 1), evidence: 'U+' + zw[0].charCodeAt(0).toString(16).toUpperCase().padStart(4, '0') + ' : ' + truncate(lines[lineOf(text, zw.index + 1) - 1], 120) }));
        const homo = /[A-Za-z][Ѐ-ӿͰ-Ͽ]|[Ѐ-ӿͰ-Ͽ][A-Za-z]/.exec(text);
        if (homo) findings.push(makeFinding(R.HOMO, { file: file.rel, line: lineOf(text, homo.index), evidence: truncate(lines[lineOf(text, homo.index) - 1], 160) }));
      }

      // Lignes longues et entropie (fichiers non minifiés uniquement)
      if (isCode && !minified) {
        const li = lines.findIndex(l => l.length > 1500);
        if (li >= 0) findings.push(makeFinding(R.LONG, { file: file.rel, line: li + 1, evidence: `${lines[li].length} caractères — fin de ligne : …${lines[li].slice(-120)}` }));
        const strRe = /(['"`])([^'"`\n]{200,})\1/g;
        let sm;
        while ((sm = strRe.exec(text))) {
          const s = sm[2];
          if (/^data:(image|font|application\/font)/.test(s) || /^[MmLlHhVvCcSsQqTtAaZz0-9.,\s-]+$/.test(s)) continue;
          if (shannonEntropy(s) > 4.8) {
            findings.push(makeFinding(R.ENTROPY, { file: file.rel, line: lineOf(text, sm.index), evidence: truncate(s, 100) + ` (longueur ${s.length}, entropie ${shannonEntropy(s).toFixed(2)})` }));
            break;
          }
        }
      }

      // Domaines externes
      const urls = extractUrls(text);
      const extHosts = [];
      for (const u of urls) {
        const h = hostOf(u);
        if (!h || isInternalHost(h, internal) || BENIGN_HOSTS.test(h)) continue;
        extHosts.push(h);
        if (!domains.has(h)) domains.set(h, { domaine: h, occurrences: 0, fichiers: new Set() });
        const d = domains.get(h); d.occurrences++; d.fichiers.add(file.rel);
      }

      // Corrélations source sensible + envoi réseau externe
      if (isCode && extHosts.length && SINKS.test(text)) {
        const strong = STRONG_SOURCES.exec(text);
        if (strong) {
          const susp = SUSPICIOUS_DOMAINS_RE.test(text);
          findings.push(makeFinding(R.EXFIL, { file: file.rel, line: lineOf(text, strong.index), severity: susp ? 'critical' : 'high', evidence: `Source : "${strong[0]}" — hôtes externes : ${[...new Set(extHosts)].slice(0, 3).join(', ')}` }));
        }
        const key = KEY_SOURCES.exec(text);
        if (key) findings.push(makeFinding(R.KEYLOG, { file: file.rel, line: lineOf(text, key.index), evidence: `${key[0]} — hôtes externes : ${[...new Set(extHosts)].slice(0, 3).join(', ')}` }));
      }

      // Scripts externes dans HTML
      if (isHtml) {
        const re = /<script\b[^>]*\bsrc\s*=\s*['"]((?:https?:)?\/\/[^'"]+)['"][^>]*>/gi;
        let m;
        while ((m = re.exec(text))) {
          const h = hostOf(m[1].startsWith('//') ? 'https:' + m[1] : m[1]);
          if (isInternalHost(h, internal)) continue;
          const integrity = /\bintegrity\s*=/.test(m[0]);
          findings.push(makeFinding(R.EXT_SCRIPT, { file: file.rel, line: lineOf(text, m.index), severity: integrity ? 'low' : 'medium', evidence: truncate(m[0], 200) }));
        }
      }

      // Ports d'écoute
      if (isCode && ctx.projectType !== 'fe') {
        const re = /\.listen\s*\(\s*(\d{2,5})\b/g;
        let m;
        while ((m = re.exec(text))) listens.push({ port: Number(m[1]), file: file.rel, line: lineOf(text, m.index) });
        if (/\.listen\s*\(/.test(text)) listens.push({ port: null, file: file.rel, line: lineOf(text, text.search(/\.listen\s*\(/)) });
      }
    }

    // angular.json
    const ngFile = ctx.files.find(f => f.base === 'angular.json');
    if (ngFile) {
      try {
        const ng = JSON.parse(ctx.readText(ngFile));
        for (const [pname, p] of Object.entries(ng.projects || {})) {
          for (const [tname, t] of Object.entries((p.architect || p.targets) || {})) {
            const confs = [t.options || {}, ...Object.values(t.configurations || {})];
            for (const o of confs) {
              for (const s of (o.scripts || [])) {
                const input = typeof s === 'string' ? s : (s.input || '');
                const distant = /^https?:|^\/\//.test(input) || input.startsWith('..') || /^[A-Za-z]:|^\//.test(input);
                findings.push(makeFinding(distant ? R.NG_SCRIPT_URL : R.NG_SCRIPTS, { file: ngFile.rel, evidence: `${pname} > ${tname} > scripts : ${input}` }));
              }
            }
            const prod = (t.configurations || {}).production;
            if (tname === 'build' && prod && (prod.sourceMap === true || (prod.sourceMap && (prod.sourceMap.scripts || prod.sourceMap.styles)))) {
              findings.push(makeFinding(R.NG_SOURCEMAP, { file: ngFile.rel, evidence: `${pname} > build > production > sourceMap : ${JSON.stringify(prod.sourceMap)}` }));
            }
          }
        }
      } catch { /* JSON invalide : ignoré */ }
      // CSP : ni balise meta dans index.html, ni en-tête dans une config serveur du dépôt
      const index = ctx.files.find(f => /(^|\/)src\/index\.html$/.test(f.rel));
      const hasMeta = index && /http-equiv=["']Content-Security-Policy/i.test(ctx.readText(index) || '');
      const hasHeader = ctx.files.some(f => /\.(conf|htaccess)$|^\.htaccess$/.test(f.base) && /Content-Security-Policy/i.test(ctx.readText(f) || ''));
      if (index && !hasMeta && !hasHeader) findings.push(makeFinding(R.NG_CSP, { file: index.rel, evidence: 'Aucune Content-Security-Policy (meta ou en-tête serveur) trouvée dans le dépôt' }));
    }
    // Service worker Angular : ressources externes mises en cache
    for (const f of ctx.files.filter(f => f.base === 'ngsw-config.json')) {
      for (const u of extractUrls(ctx.readText(f) || '')) {
        const h = hostOf(u);
        if (h && !isInternalHost(h, internal) && !BENIGN_HOSTS.test(h)) findings.push(makeFinding(R.NGSW_EXT, { file: f.rel, evidence: u }));
      }
    }
    // proxy.conf
    for (const f of ctx.files.filter(f => /^proxy\.conf(\.\w+)?\.(json|js|mjs|cjs)$/.test(f.base))) {
      const t = ctx.readText(f) || '';
      for (const u of extractUrls(t)) {
        const h = hostOf(u);
        if (!isInternalHost(h, internal)) findings.push(makeFinding(R.PROXY_EXT, { file: f.rel, evidence: u }));
      }
    }
    // Ports
    const explicit = listens.filter(l => l.port);
    for (const l of explicit) {
      if (!ctx.config.ports.attendus.includes(l.port)) findings.push(makeFinding(R.PORT, { file: l.file, line: l.line, evidence: `.listen(${l.port})` }));
    }
    const listenFiles = listens.filter(l => !l.port);
    if (listenFiles.length > 1) findings.push(makeFinding(R.MULTI_LISTEN, { file: listenFiles[0].file, evidence: listenFiles.map(l => `${l.file}:${l.line}`).join(', ') }));

    const domaines = [...domains.values()].map(d => ({ domaine: d.domaine, occurrences: d.occurrences, fichiers: [...d.fichiers].slice(0, 5) })).sort((a, b) => b.occurrences - a.occurrences);
    const ports = explicit.map(l => ({ port: l.port, source: 'code (.listen)', fichier: l.file, ligne: l.line }));
    return { findings, filesAnalyzed: count, inventory: { domaines, ports }, notes: [] };
  },
};

module.exports.RULES = RULES;
module.exports.MINIFIED_RULES = MINIFIED_RULES;
