'use strict';
const { scanText } = require('../lib/patterns');
const { SHELL_RULES } = require('../lib/shell-rules');
const { makeFinding } = require('../lib/finding');
const { hostOf, isInternalHost, isIp, parsePort } = require('../lib/util');

const S = 'serveur';
const R = {
  PORT: { id: 'SRV_PORT_INATTENDU', sev: 'medium', review: true, title: 'Port d\'écoute inhabituel', desc: 'Le serveur écoute sur un port non standard : service caché possible.', fix: 'Vérifier le besoin de ce port.' },
  PROXY_EXT: { id: 'SRV_PROXY_EXTERNE', sev: 'high', review: true, title: 'Redirection de trafic (proxy) vers un hôte externe', desc: 'Les requêtes (et leurs en-têtes : cookies, tokens) sont relayées vers un hôte hors de l\'entreprise.', fix: 'Vérifier que l\'hôte cible est légitime et attendu.' },
  PROXY_IP: { id: 'SRV_PROXY_IP_PUBLIQUE', sev: 'high', review: true, title: 'Proxy vers une adresse IP publique', desc: 'Le trafic est relayé vers une IP publique codée en dur.', fix: 'Vérifier la destination.' },
  PROXY_VAR: { id: 'SRV_PROXY_DYNAMIQUE', sev: 'medium', review: true, title: 'Cible de proxy calculée dynamiquement', desc: 'Une cible variable peut transformer le serveur en proxy ouvert (SSRF).', fix: 'Fixer la cible ou valider strictement la variable.' },
  PROXY_USER: { id: 'SRV_PROXY_OUVERT', sev: 'critical', title: 'Proxy ouvert contrôlé par la requête', desc: 'La cible du proxy dépend d\'un paramètre ou d\'un en-tête de la requête : n\'importe qui peut faire relayer du trafic (SSRF, accès au réseau interne).', fix: 'Supprimer immédiatement.' },
  SCRIPTING: { id: 'SRV_SCRIPT_EMBARQUE', sev: 'high', review: true, title: 'Code exécuté par le serveur web (lua / perl / njs)', desc: 'Du code arbitraire s\'exécute dans le serveur web pour chaque requête : emplacement idéal pour une backdoor.', fix: 'Relire intégralement le code embarqué.' },
  MIRROR: { id: 'SRV_MIRROR', sev: 'high', review: true, title: 'Duplication du trafic (mirror)', desc: 'Chaque requête est copiée vers une autre destination : peut servir à exfiltrer le trafic.', fix: 'Vérifier la destination du mirror.' },
  INJECTION: { id: 'SRV_INJECTION_CONTENU', sev: 'high', review: true, title: 'Injection de contenu dans les réponses (sub_filter / add_after_body)', desc: 'Le serveur modifie les pages servies : technique d\'injection de script malveillant.', fix: 'Vérifier le contenu injecté.' },
  LOG_EXT: { id: 'SRV_JOURNAUX_EXTERNES', sev: 'high', review: true, title: 'Journaux envoyés vers un serveur externe', desc: 'Les journaux (URL, en-têtes, IP) partent vers un serveur syslog externe.', fix: 'Vérifier la destination.' },
  AUTOINDEX: { id: 'SRV_LISTING_REPERTOIRE', sev: 'medium', title: 'Listing des répertoires activé', desc: 'Le contenu des répertoires est affiché publiquement.', fix: 'Désactiver (autoindex off / Options -Indexes).' },
  ALIAS: { id: 'SRV_ALIAS_TRAVERSAL', sev: 'medium', title: 'Alias vulnérable à la traversée de répertoire', desc: 'location sans "/" final combinée à alias : permet de lire des fichiers hors du dossier (ex. /static../etc).', fix: 'Terminer location et alias par "/".' },
  TOKENS: { id: 'SRV_VERSION_EXPOSEE', sev: 'low', title: 'Version du serveur exposée', desc: 'La version du serveur facilite le ciblage de vulnérabilités connues.', fix: 'server_tokens off / ServerTokens Prod / ServerSignature Off.' },
  CORS: { id: 'SRV_CORS_OUVERT', sev: 'medium', title: 'CORS ouvert à toutes les origines', desc: 'N\'importe quel site peut appeler ces ressources depuis le navigateur d\'un utilisateur.', fix: 'Restreindre aux origines connues.' },
  CORS_REFLECT: { id: 'SRV_CORS_REFLECHI', sev: 'high', title: 'CORS reflétant l\'origine de la requête', desc: 'L\'origine appelante est renvoyée telle quelle : équivaut à autoriser tous les sites, avec cookies.', fix: 'Utiliser une liste blanche d\'origines.' },
  REDIRECT_EXT: { id: 'SRV_REDIRECTION_EXTERNE', sev: 'medium', review: true, title: 'Redirection vers un domaine externe', desc: 'Des utilisateurs sont redirigés vers un domaine externe (hameçonnage possible).', fix: 'Vérifier la destination.' },
  INCLUDE: { id: 'SRV_INCLUDE_SUSPECT', sev: 'high', review: true, title: 'Inclusion d\'une configuration depuis un emplacement inhabituel', desc: 'Une configuration est chargée depuis /tmp, /dev/shm, /home… : emplacement modifiable à l\'exécution.', fix: 'N\'inclure que des fichiers sous /etc/nginx ou /etc/apache2.' },
  ROOT_SYS: { id: 'SRV_RACINE_SYSTEME', sev: 'high', title: 'Racine web pointant vers un dossier système', desc: 'root ou DocumentRoot pointe vers /, /etc, /root… : exposition de fichiers système.', fix: 'Pointer vers le dossier de l\'application uniquement.' },
  STATUS: { id: 'SRV_PAGE_STATUT', sev: 'low', review: true, title: 'Page de statut du serveur exposée', desc: 'stub_status / server-status / server-info révèlent des informations internes.', fix: 'Restreindre l\'accès aux IP internes.' },
  HEADERS: { id: 'SRV_ENTETES_SECURITE', sev: 'low', title: 'En-têtes de sécurité absents', desc: 'Les en-têtes protègent contre le clickjacking, le sniffing MIME et l\'injection de scripts tiers.', fix: 'Ajouter Content-Security-Policy, X-Frame-Options (ou frame-ancestors), X-Content-Type-Options.' },
  TLS_OLD: { id: 'SRV_TLS_OBSOLETE', sev: 'medium', title: 'Protocole TLS obsolète autorisé', desc: 'SSLv3 / TLS 1.0 / 1.1 sont vulnérables.', fix: 'N\'autoriser que TLSv1.2 et TLSv1.3.' },
  CGI: { id: 'SRV_CGI', sev: 'high', review: true, title: 'Exécution CGI / handler activé', desc: 'Le serveur peut exécuter des scripts déposés dans un dossier : vecteur classique de webshell.', fix: 'Désactiver CGI si non nécessaire.' },
  PHP_IMG: { id: 'SRV_PHP_SUR_EXTENSION_ANODINE', sev: 'critical', title: 'Extension anodine exécutée comme PHP', desc: 'Des fichiers .jpg/.png/.txt… sont exécutés comme du PHP : technique classique de webshell déguisé.', fix: 'Supprimer immédiatement.' },
  PHP_PREPEND: { id: 'SRV_PHP_AUTO_PREPEND', sev: 'critical', title: 'auto_prepend_file / auto_append_file', desc: 'Un fichier est exécuté avant/après chaque script PHP : persistance de backdoor.', fix: 'Supprimer.' },
  LOG_PIPE: { id: 'SRV_JOURNAL_PIPE_COMMANDE', sev: 'critical', title: 'Journal redirigé vers une commande (piped log)', desc: 'Apache exécute la commande indiquée et lui transmet les journaux : exécution de commande persistante.', fix: 'Supprimer sauf outil de rotation standard (rotatelogs) documenté.' },
  SETENV: { id: 'SRV_SETENV_DANGEREUX', sev: 'critical', title: 'Variable d\'environnement dangereuse définie par le serveur', desc: 'LD_PRELOAD / NODE_OPTIONS permettent de charger du code dans les processus.', fix: 'Supprimer.' },
  EXTFILTER: { id: 'SRV_FILTRE_EXTERNE', sev: 'critical', review: true, title: 'Filtre externe exécutant une commande (ExtFilterDefine)', desc: 'Chaque réponse passe par une commande système.', fix: 'Supprimer sauf justification.' },
  MODULE: { id: 'SRV_MODULE_SENSIBLE', sev: 'high', review: true, title: 'Chargement d\'un module sensible ou depuis un emplacement inhabituel', desc: 'Modules permettant l\'exécution de code (lua, perl, cgi, ext_filter) ou module chargé hors des dossiers standards.', fix: 'Vérifier le besoin.' },
  SUPERVISOR: { id: 'SRV_PROGRAMME_SUPERVISE', sev: 'medium', review: true, title: 'Programme lancé par supervisord', desc: 'supervisord lance et relance automatiquement ce programme.', fix: 'Vérifier chaque programme lancé.' },
};
for (const r of Object.values(R)) r.cat = S;

const EXT_RE = /^\.?(jpe?g|png|gif|ico|txt|css|js|html?|svg|bmp|webp|woff2?|json|xml)$/i;

function proxyTargetFinding(target, file, n, line, internal) {
  if (/\$(arg_|http_|cookie_|request_uri|uri\b|query_string|args\b)/.test(target)) return makeFinding(R.PROXY_USER, { file, line: n, evidence: line });
  if (target.includes('$') && !/^https?:\/\/[\w.-]+/.test(target.replace(/\$\w+/g, 'x'))) return makeFinding(R.PROXY_VAR, { file, line: n, evidence: line });
  const url = /^[a-z]+:\/\//i.test(target) ? target : 'http://' + target;
  const h = hostOf(url.replace(/\$\{?\w+\}?/g, 'variable'));
  if (!h || h === 'variable' || isInternalHost(h, internal)) return null;
  if (isIp(h)) return makeFinding(R.PROXY_IP, { file, line: n, evidence: line });
  return makeFinding(R.PROXY_EXT, { file, line: n, evidence: line, description: `${R.PROXY_EXT.desc} Hôte : ${h}.` });
}

function analyzeNginx(text, file, ctx, offset = 0) {
  const findings = [];
  const ports = [];
  const internal = ctx.config.domaines.internes || [];
  const lines = text.split(/\r?\n/);
  let currentLocation = null;
  let hasServer = false;
  const at = (rule, n, l, data) => findings.push(makeFinding(rule, Object.assign({ file, line: n + offset, evidence: l.trim() }, data)));
  lines.forEach((raw, i) => {
    const l = raw.replace(/(^|\s)#.*$/, '');
    const n = i + 1;
    if (!l.trim()) return;
    if (/^\s*server\s*\{/.test(l)) hasServer = true;
    let m;
    if ((m = /^\s*listen\s+([^;]+);/.exec(l))) {
      const port = parsePort(m[1].replace(/\[[^\]]*\]:?/, ' '));
      if (port) {
        ports.push({ port, source: 'nginx', fichier: file, ligne: n + offset });
        if (!ctx.config.ports.attendus.includes(port)) at(R.PORT, n, l, { description: `${R.PORT.desc} Port : ${port}.` });
      }
    }
    if ((m = /\b(proxy|fastcgi|uwsgi|grpc|scgi)_pass\s+([^;\s]+)\s*;/.exec(l))) {
      const f = proxyTargetFinding(m[2], file, n + offset, l.trim(), internal); if (f) findings.push(f);
    }
    if ((m = /^\s*server\s+([^\s;]+)[^;]*;/.exec(l)) && !/\{/.test(l)) {
      const f = proxyTargetFinding(m[1], file, n + offset, l.trim(), internal); if (f) findings.push(f);
    }
    if (/\b(\w+_by_lua(_block|_file)?|lua_\w+|perl_\w+|perl\s+\S|js_(content|import|set|include|body_filter|header_filter|access))\b/.test(l)) at(R.SCRIPTING, n, l);
    if ((m = /^\s*load_module\s+([^;]+);/.exec(l)) && (/lua|perl|njs|js_module/i.test(m[1]) || !/^\s*(modules\/|\/usr\/(lib|share)\/nginx\/|\/etc\/nginx\/modules)/.test(m[1]))) at(R.MODULE, n, l);
    if (/^\s*mirror\s+\//.test(l)) at(R.MIRROR, n, l);
    if (/^\s*(sub_filter\s|add_before_body|add_after_body)/.test(l)) at(R.INJECTION, n, l, { severity: /<script|https?:\/\//i.test(l) ? 'high' : 'medium' });
    if ((m = /(access_log|error_log)\s+syslog:server=([^,;\s]+)/.exec(l))) {
      const h = m[2].split(':')[0].replace(/^\[|\]$/g, '');
      if (!isInternalHost(h, internal)) at(R.LOG_EXT, n, l);
    }
    if (/^\s*autoindex\s+on\s*;/.test(l)) at(R.AUTOINDEX, n, l);
    if ((m = /^\s*location\s+(?:[=^~*]+\s*)?(\S+)\s*\{/.exec(l))) currentLocation = { path: m[1], n };
    if (currentLocation && (m = /(?:^|[{;])\s*alias\s+([^;]+);/.exec(l))) {
      if (!currentLocation.path.endsWith('/') && m[1].trim().endsWith('/') && !/[~*]/.test(currentLocation.path)) at(R.ALIAS, n, l, { evidence: `location ${currentLocation.path} … ${l.trim()}` });
    }
    if (/^\s*server_tokens\s+on\s*;/.test(l)) at(R.TOKENS, n, l);
    if (/Access-Control-Allow-Origin["']?\s+["']?\*/.test(l)) at(R.CORS, n, l);
    if (/Access-Control-Allow-Origin["']?\s+["']?\$http_origin/.test(l)) at(R.CORS_REFLECT, n, l);
    if ((m = /(return\s+30[1278]|rewrite\s+\S+)\s+["']?(https?:\/\/[^\s;"']+)/.exec(l))) {
      const h = hostOf(m[2]);
      if (h && !h.includes('$') && !isInternalHost(h, internal)) at(R.REDIRECT_EXT, n, l);
    }
    if ((m = /^\s*include\s+([^;]+);/.exec(l)) && /^\s*\/(tmp|var\/tmp|dev\/shm|home|root|opt\/[^/]*\/tmp)\b/.test(m[1])) at(R.INCLUDE, n, l);
    if (/^\s*root\s+\/(etc|root|home|proc|var\/run|var\/lib)?\/?\s*;/.test(l)) at(R.ROOT_SYS, n, l);
    if (/^\s*stub_status\b/.test(l)) at(R.STATUS, n, l);
    if (/^\s*ssl_protocols\b[^;]*\b(SSLv2|SSLv3|TLSv1|TLSv1\.1)\b(?!\.)/.test(l) && /\b(SSLv2|SSLv3|TLSv1(?![.\d])|TLSv1\.1)\b/.test(l)) at(R.TLS_OLD, n, l);
  });
  if (hasServer) {
    const missing = [];
    if (!/Content-Security-Policy/i.test(text)) missing.push('Content-Security-Policy');
    if (!/X-Frame-Options|frame-ancestors/i.test(text)) missing.push('X-Frame-Options');
    if (!/X-Content-Type-Options/i.test(text)) missing.push('X-Content-Type-Options');
    if (missing.length) findings.push(makeFinding(R.HEADERS, { file, evidence: 'Absents : ' + missing.join(', ') }));
  }
  return { findings, ports };
}

function analyzeApache(text, file, ctx, offset = 0) {
  const findings = [];
  const ports = [];
  const internal = ctx.config.domaines.internes || [];
  const at = (rule, n, l, data) => findings.push(makeFinding(rule, Object.assign({ file, line: n + offset, evidence: l.trim() }, data)));
  let hasVhost = false;
  text.split(/\r?\n/).forEach((raw, i) => {
    const l = raw.replace(/^\s*#.*$/, '');
    const n = i + 1;
    if (!l.trim()) return;
    let m;
    if (/<VirtualHost/i.test(l)) hasVhost = true;
    if ((m = /^\s*Listen\s+(\S+)/i.exec(l))) {
      const port = parsePort(m[1]);
      if (port) {
        ports.push({ port, source: 'apache', fichier: file, ligne: n + offset });
        if (!ctx.config.ports.attendus.includes(port)) at(R.PORT, n, l, { description: `${R.PORT.desc} Port : ${port}.` });
      }
    }
    if (/^\s*(ScriptAlias(Match)?\s|AddHandler\s+cgi-script|SetHandler\s+cgi-script)|Options\s+[^#\n]*\+?ExecCGI/i.test(l)) at(R.CGI, n, l);
    if ((m = /^\s*(AddType|AddHandler)\s+application\/x-httpd-php[\w-]*\s+(.+)$/i.exec(l))) {
      const exts = m[2].split(/\s+/);
      if (exts.some(e => EXT_RE.test(e))) at(R.PHP_IMG, n, l);
      else at(R.CGI, n, l);
    }
    if (/^\s*<FilesMatch[^>]*\.(jpe?g|png|gif|ico|txt)/i.test(l) && /SetHandler\s+application\/x-httpd-php/i.test(text)) at(R.PHP_IMG, n, l);
    if (/php_(admin_)?value\s+auto_(prepend|append)_file/i.test(l)) at(R.PHP_PREPEND, n, l);
    if (/^\s*(CustomLog|ErrorLog|TransferLog|GlobalLog)\s+["']?\|/i.test(l) && !/\|\s*["']?\$?\s*\/?[\w/]*rotatelogs\b/i.test(l)) at(R.LOG_PIPE, n, l);
    if ((m = /^\s*RewriteRule\s+\S+\s+["']?(https?:\/\/[^\s"']+)["']?\s*(\[[^\]]*\])?/i.exec(l))) {
      const h = hostOf(m[1]);
      if (h && !isInternalHost(h, internal)) at(/\bP\b/.test(m[2] || '') ? R.PROXY_EXT : R.REDIRECT_EXT, n, l);
    }
    if ((m = /^\s*ProxyPass(Reverse|Match)?\s+\S+\s+["']?([a-z]+:\/\/[^\s"']+)/i.exec(l))) {
      const f = proxyTargetFinding(m[2], file, n + offset, l.trim(), internal); if (f) findings.push(f);
    }
    if (/^\s*Options\s+[^#\n]*(?<![-\w])\+?Indexes\b/i.test(l)) at(R.AUTOINDEX, n, l);
    if (/Header\s+(always\s+)?set\s+Access-Control-Allow-Origin\s+["']?\*/i.test(l)) at(R.CORS, n, l);
    if (/^\s*SetEnv(If\w*)?\s+.*\b(LD_PRELOAD|NODE_OPTIONS)\b/i.test(l)) at(R.SETENV, n, l);
    if (/^\s*ExtFilterDefine\b/i.test(l)) at(R.EXTFILTER, n, l);
    if ((m = /^\s*LoadModule\s+\S+\s+(\S+)/i.exec(l)) && (/mod_(lua|perl|cgid?|ext_filter|python)\b/i.test(m[1]) || /^["']?\/(tmp|var\/tmp|dev\/shm|home)/.test(m[1]))) at(R.MODULE, n, l);
    if (/^\s*(ServerSignature\s+On|ServerTokens\s+(Full|OS))/i.test(l)) at(R.TOKENS, n, l);
    if (/SetHandler\s+server-(status|info)/i.test(l)) at(R.STATUS, n, l);
    if (/^\s*DocumentRoot\s+["']?\/(etc|root|home|proc)?\/?["']?\s*$/i.test(l)) at(R.ROOT_SYS, n, l);
    if (/^\s*SSLProtocol\b/i.test(l) && /(?<!-)\b(SSLv3|TLSv1(?![.\d])|TLSv1\.1)\b/.test(l.replace(/-(SSLv3|TLSv1(\.1)?)/g, '')) && !/^\s*SSLProtocol\s+all\s+-/i.test(l)) at(R.TLS_OLD, n, l);
  });
  if (hasVhost) {
    const missing = [];
    if (!/Content-Security-Policy/i.test(text)) missing.push('Content-Security-Policy');
    if (!/X-Frame-Options|frame-ancestors/i.test(text)) missing.push('X-Frame-Options');
    if (!/X-Content-Type-Options/i.test(text)) missing.push('X-Content-Type-Options');
    if (missing.length) findings.push(makeFinding(R.HEADERS, { file, evidence: 'Absents : ' + missing.join(', ') }));
  }
  return { findings, ports };
}

function analyzeSupervisor(text, file, offset = 0) {
  const out = [];
  text.split(/\r?\n/).forEach((l, i) => {
    if (/^\s*command\s*=/.test(l)) out.push(makeFinding(R.SUPERVISOR, { file, line: i + 1 + offset, evidence: l.trim() }));
  });
  return out;
}

function kindOf(text, base) {
  // Sensible à la casse : "listen 80;" (nginx) ne doit pas être confondu avec "Listen 80" (apache)
  if (base === '.htaccess' || /<VirtualHost|<Directory|^\s*RewriteRule\s|^\s*ProxyPass(Reverse|Match)?\s|^\s*Listen\s+\d|^\s*LoadModule\s|^\s*DocumentRoot\s/m.test(text)) return 'apache';
  if (/^\s*\[(program|supervisord):/m.test(text)) return 'supervisor';
  if (/\b(server|location|upstream|http)\s*[^{;]*\{|proxy_pass|listen\s+\d+\s*;|worker_processes/.test(text)) return 'nginx';
  return null;
}

function isServerConfigFile(f) {
  if (f.base === '.htaccess') return true;
  if (/\.(conf|vhost|nginx|conf\.template|conf\.tpl)$/i.test(f.base)) return true;
  if (/(^|\/)(nginx|apache2?|httpd|conf\.d|sites-(available|enabled))\//i.test(f.rel) && !f.ext) return true;
  return false;
}

module.exports = {
  id: 'server-config',
  label: 'Configurations serveur (nginx, apache, supervisord)',
  category: S,
  controls: [
    'Ports d\'écoute (listen / Listen) et ports inhabituels',
    'Proxy vers des hôtes externes, IP publiques, cibles dynamiques ou contrôlées par la requête (proxy ouvert)',
    'Code embarqué (lua, perl, njs), modules sensibles, mirror du trafic, injection de contenu (sub_filter)',
    'Journaux envoyés vers l\'extérieur ou vers une commande (piped logs)',
    'Apache : CGI, PHP sur extensions d\'images, auto_prepend_file, ExtFilterDefine, SetEnv LD_PRELOAD',
    'Listing de répertoires, alias traversal, racine système, pages de statut, version exposée, TLS obsolète',
    'CORS ouvert ou réfléchi, redirections externes, en-têtes de sécurité',
    'Programmes lancés par supervisord ; motifs shell dangereux dans toutes ces configurations',
  ],
  analyzeNginx, analyzeApache, analyzeSupervisor, kindOf,
  async run(ctx) {
    const findings = [];
    const ports = [];
    let count = 0;
    for (const file of ctx.files.filter(isServerConfigFile)) {
      const text = ctx.readText(file);
      if (!text) continue;
      const kind = kindOf(text, file.base);
      if (!kind) continue;
      count++;
      let r = { findings: [], ports: [] };
      if (kind === 'nginx') r = analyzeNginx(text, file.rel, ctx);
      else if (kind === 'apache') r = analyzeApache(text, file.rel, ctx);
      else r.findings = analyzeSupervisor(text, file.rel);
      findings.push(...r.findings);
      ports.push(...r.ports);
      findings.push(...scanText(text, SHELL_RULES, { file: file.rel, category: S, projectType: ctx.projectType }));
    }
    return { findings, filesAnalyzed: count, inventory: { ports }, notes: count ? [] : ['Aucun fichier de configuration serveur trouvé à la racine du dépôt (les configurations embarquées dans des ConfigMaps sont analysées par le scanner Helm/Kubernetes).'] };
  },
};
