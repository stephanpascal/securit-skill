'use strict';
/**
 * Règles partagées : commandes shell dangereuses et indicateurs réseau.
 * Utilisées sur : Dockerfile, scripts .sh/.ps1, scripts npm, YAML (Helm, k8s, CI), configs serveur.
 * IMPORTANT : pas de drapeau 'g' sur les regex (exec() avec lastIndex).
 */
const { isInternalHost, isIp, hostOf } = require('./util');
const IOC = require('../rules/ioc.json');
const escapeRe = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const IOC_DOMAINS_RE = (IOC.domaines || []).length ? new RegExp('\\b(' + IOC.domaines.map(escapeRe).join('|') + ')\\b', 'i') : null;

const SUSPICIOUS_DOMAINS_RE = /\b(pastebin\.com|paste\.ee|hastebin\.|ghostbin\.|transfer\.sh|file\.io|temp\.sh|0x0\.st|anonfiles\.|ngrok(-free)?\.(io|app|dev)|serveo\.net|localtunnel\.me|loca\.lt|trycloudflare\.com|webhook\.site|requestbin\.|pipedream\.net|hookbin\.|beeceptor\.com|burpcollaborator\.net|oastify\.com|interact\.sh|oast\.(pro|live|site|online|fun|me)|canarytokens\.|dnslog\.cn|ceye\.io|discord(app)?\.com\/api\/webhooks|api\.telegram\.org\/bot|bit\.ly\/|tinyurl\.com|is\.gd\/|iplogger\.|grabify\.|ipinfo\.io|ip-api\.com|ifconfig\.me|icanhazip\.com|api\.ipify\.org|[a-z2-7]{16,56}\.onion\b|mega\.nz)/i;

const NET_RULES = [
  ...(IOC_DOMAINS_RE ? [{
    id: 'NET_DOMAINE_IOC', sev: 'critical', cat: 'code',
    re: IOC_DOMAINS_RE,
    title: 'Domaine connu d\'une campagne malveillante (IOC)',
    desc: 'Ce domaine figure dans la liste des indicateurs de compromission (rules/ioc.json).',
    fix: 'Supprimer et investiguer l\'origine ; considérer les postes et la CI concernés comme compromis.',
  }] : []),
  {
    id: 'NET_SUSPICIOUS_DOMAIN', sev: 'high', cat: 'code', review: true,
    re: SUSPICIOUS_DOMAINS_RE,
    title: 'Domaine suspect (exfiltration, tunnel, collecteur, raccourcisseur)',
    desc: 'Ce domaine est typiquement utilisé pour exfiltrer des données, recevoir des callbacks, héberger une charge malveillante ou masquer une URL.',
    fix: 'Vérifier la légitimité de cet appel. Aucun projet applicatif ne devrait contacter ce type de service.',
  },
  {
    id: 'NET_PUBLIC_IP_URL', sev: 'high', cat: 'code', review: true,
    re: /\b(?:https?|wss?|ftp|tcp|udp):\/\/((?:\d{1,3}\.){3}\d{1,3})/i,
    filter: (line, m) => !isInternalHost(m[1]),
    title: 'URL vers une adresse IP publique codée en dur',
    desc: 'Les logiciels malveillants contactent souvent une IP en dur pour éviter la résolution DNS et la surveillance.',
    fix: 'Remplacer par un nom de domaine maîtrisé et vérifier la destination de cette IP.',
  },
  {
    id: 'NET_CLOUD_METADATA', sev: 'high', cat: 'code', review: true,
    re: /169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200/,
    title: 'Accès au service de métadonnées cloud',
    desc: 'L\'accès à l\'API de métadonnées permet de voler les identifiants du nœud ou du pod (technique SSRF/vol de credentials).',
    fix: 'Supprimer cet accès s\'il n\'est pas justifié.',
  },
  {
    id: 'NET_DETOURNEMENT_AGENT_IA', sev: 'critical', cat: 'code',
    re: /\b(claude|gemini|q|codex|copilot|cursor-agent|aider|opencode)\b[^\n]{0,200}(--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo|--trust-all-tools|--allow-all-tools|--full-auto|--approval-mode[= ]yolo)/i,
    title: 'Pilotage d\'un assistant IA en mode sans confirmation',
    desc: 'Un assistant IA installé sur le poste (Claude, Gemini, Amazon Q, Codex…) est lancé avec ses garde-fous désactivés : technique de l\'attaque s1ngularity (Nx, 2025) pour faire inventorier et voler les secrets par l\'IA.',
    fix: 'Supprimer immédiatement ; aucun code applicatif ou script d\'installation ne doit piloter un assistant IA.',
  },
  {
    id: 'NET_C2_BLOCKCHAIN', sev: 'high', cat: 'code', review: true,
    re: /\b(eth_call|eth_getStorageAt|getStorageAt|eth_getTransactionByHash|getSignaturesForAddress)\b|(mainnet\.infura\.io|\.alchemy(api)?\.io\/v2|bsc-dataseed[\w.-]*\.binance\.org|api\.mainnet-beta\.solana\.com|rpc\.ankr\.com|cloudflare-eth\.com|api\.trongrid\.io|eth\.llamarpc\.com|ethereum-rpc\.publicnode\.com)/i,
    title: 'Lecture de données sur une blockchain (serveur de commande caché possible)',
    desc: 'Technique EtherHiding / NullReceiver : l\'adresse du serveur de l\'attaquant ou la charge est lue dans un smart contract ou une transaction, ce qui la rend impossible à bloquer ou supprimer.',
    fix: 'Inattendu dans une application qui ne manipule pas de cryptomonnaie : vérifier ce qui est lu et ce qui en est fait.',
  },
  {
    id: 'NET_CRYPTO_MINER', sev: 'critical', cat: 'code',
    re: /\b(xmrig|minerd|cpuminer|cryptonight|coinhive|coinimp|nicehash|stratum\+(tcp|ssl):\/\/|webminepool|cryptoloot)\b/i,
    title: 'Référence à un mineur de cryptomonnaie',
    desc: 'Présence d\'un indicateur de minage (logiciel, pool stratum ou bibliothèque de minage navigateur).',
    fix: 'Supprimer immédiatement et rechercher l\'origine de l\'introduction (historique git).',
  },
];

const SHELL_RULES = [
  {
    id: 'SH_PIPE_TO_SHELL', sev: 'critical', cat: 'shell',
    re: /\b(curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|;&]*\|\s*(sudo\s+)?((ba|z|da|k)?sh|python[23]?|node|perl|ruby|php|iex|Invoke-Expression)\b/i,
    title: 'Téléchargement exécuté directement (curl | sh)',
    desc: 'Un contenu téléchargé est exécuté sans aucune vérification : la source distante peut livrer n\'importe quel code à chaque exécution.',
    fix: 'Télécharger un artefact versionné, vérifier son empreinte (sha256) puis l\'exécuter, ou l\'intégrer au dépôt.',
  },
  {
    id: 'SH_REVERSE_SHELL', sev: 'critical', cat: 'shell',
    re: /\/dev\/(tcp|udp)\/|\bnc(at)?\b[^\n]*\s-[a-z]*[ec]\s|\bsocat\b[^\n]*\b(exec|system):|\bmkfifo\b|\b(ba)?sh\s+-i\s*[<>]&|\bpty\.spawn\b|\bTCPClient\s*\(/i,
    title: 'Motif de reverse shell / backdoor réseau',
    desc: 'Commande typique d\'ouverture d\'un shell distant (bash /dev/tcp, nc -e, socat exec, mkfifo).',
    fix: 'Supprimer immédiatement. Considérer l\'environnement comme compromis et investiguer l\'historique.',
  },
  {
    id: 'SH_BASE64_EXEC', sev: 'critical', cat: 'shell',
    re: /base64\s+(-d|--decode|-D)\b[^\n]*\|\s*((ba|z)?sh|python|node|perl)\b|echo\s+['"]?[A-Za-z0-9+\/]{60,}={0,2}['"]?\s*\|\s*base64|FromBase64String\s*\(|-enc(odedcommand)?\s+[A-Za-z0-9+\/=]{30,}/i,
    title: 'Contenu encodé en base64 puis exécuté',
    desc: 'L\'encodage base64 sert à masquer une commande malveillante aux relectures et aux outils.',
    fix: 'Décoder le contenu pour l\'examiner, puis le supprimer ou le remplacer par une commande lisible.',
  },
  {
    id: 'SH_EVAL_REMOTE', sev: 'critical', cat: 'shell',
    re: /\beval\s+["'`]?\$\(\s*(curl|wget)|\bsource\s+<\(\s*(curl|wget)|\.\s+<\(\s*(curl|wget)/i,
    title: 'Évaluation d\'un script distant (eval $(curl …))',
    desc: 'Le résultat d\'un téléchargement est évalué par le shell.',
    fix: 'Supprimer : aucune exécution de code distant non vérifié.',
  },
  {
    id: 'SH_DOWNLOAD_THEN_EXEC', sev: 'high', cat: 'shell', review: true,
    re: /\b(curl|wget)\b[^\n]*(\s-o\s?|\s-O\b|\s>\s?)\s*\S+[^\n]*(&&|;)\s*(chmod\s+\+?[0-7x]+|(ba)?sh\s|\.\/|node\s|python)/i,
    title: 'Fichier téléchargé puis exécuté',
    desc: 'Un fichier est téléchargé puis rendu exécutable ou exécuté dans la même commande.',
    fix: 'Vérifier l\'URL et ajouter une vérification d\'empreinte (sha256sum -c).',
  },
  {
    id: 'SH_LD_PRELOAD', sev: 'critical', cat: 'shell',
    re: /\bLD_PRELOAD\b|\/etc\/ld\.so\.preload/,
    title: 'Injection de bibliothèque (LD_PRELOAD)',
    desc: 'LD_PRELOAD permet de charger une bibliothèque dans tous les processus : technique classique de rootkit.',
    fix: 'Supprimer, sauf justification technique documentée.',
  },
  {
    id: 'SH_PERSISTENCE_CRON', sev: 'high', cat: 'shell', review: true,
    re: /\bcrontab\b|\/etc\/cron|\/var\/spool\/cron|systemctl\s+enable|\/etc\/systemd\/system|\/etc\/init\.d\/|\/etc\/rc\.local|\.bashrc|\.profile\b/,
    title: 'Mécanisme de persistance (cron, systemd, rc, profil shell)',
    desc: 'Mise en place d\'une tâche planifiée ou d\'un démarrage automatique : technique de persistance d\'une backdoor.',
    fix: 'Un conteneur applicatif ne doit pas installer de tâches planifiées. Vérifier la légitimité.',
  },
  {
    id: 'SH_SSH_ACCESS', sev: 'high', cat: 'shell', review: true,
    re: /authorized_keys|\.ssh\/id_|ssh-keygen|\bsshd\b|openssh-server|dropbear/,
    title: 'Manipulation de clés ou de serveur SSH',
    desc: 'Ajout de clés autorisées ou d\'un serveur SSH : porte d\'entrée persistante.',
    fix: 'Supprimer : un conteneur applicatif n\'a pas besoin de SSH.',
  },
  {
    id: 'SH_TLS_DISABLED', sev: 'high', cat: 'shell',
    re: /NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0|strict-ssl\s*[= ]\s*false|\s--insecure\b|\bcurl\b[^\n]*\s-k\b|--no-check-certificate|GIT_SSL_NO_VERIFY|sslVerify\s*=?\s*false|--trusted-host/i,
    title: 'Vérification TLS désactivée',
    desc: 'Désactiver la vérification des certificats permet une interception (man-in-the-middle) et l\'injection de contenu.',
    fix: 'Réactiver la vérification TLS et installer le certificat d\'entreprise (NODE_EXTRA_CA_CERTS).',
  },
  {
    id: 'SH_HISTORY_WIPE', sev: 'high', cat: 'shell',
    re: /history\s+-c\b|unset\s+HISTFILE|HISTFILE=\/dev\/null|rm\s+-[rf]+\s+[^\n]*(\.bash_history|\/var\/log)|\bshred\b|Clear-History|wevtutil\s+cl/i,
    title: 'Effacement de traces (historique, journaux)',
    desc: 'Effacer l\'historique ou les journaux est un comportement d\'attaquant.',
    fix: 'Supprimer et investiguer.',
  },
  {
    id: 'SH_SETUID', sev: 'high', cat: 'shell',
    re: /\bchmod\s+(-R\s+)?([ugoa]*\+s\b|[2467][0-7]{3}\b)/,
    title: 'Bit setuid/setgid positionné',
    desc: 'Un binaire setuid permet une élévation de privilèges.',
    fix: 'Supprimer le bit setuid sauf nécessité absolue.',
  },
  {
    id: 'SH_CHMOD_777', sev: 'medium', cat: 'shell',
    re: /\bchmod\s+(-R\s+)?(0?777|a\+rwx)\b/,
    title: 'Permissions 777',
    desc: 'Fichiers modifiables par tous : facilite le remplacement de code à l\'exécution.',
    fix: 'Utiliser des permissions minimales (755 / 644).',
  },
  {
    id: 'SH_NET_TOOLS', sev: 'medium', cat: 'shell', review: true,
    re: /\b(apk|apt(-get)?|yum|dnf|microdnf|zypper)\b[^\n]*\b(install|add)\b[^\n]*\b(netcat(-openbsd|-traditional)?|ncat|nmap|socat|tcpdump|telnet|proxychains|tor|masscan|hydra)\b/,
    title: 'Installation d\'outils réseau offensifs',
    desc: 'netcat, socat, nmap… n\'ont pas leur place dans une image applicative et servent souvent de backdoor.',
    fix: 'Retirer ces paquets de l\'image.',
  },
  {
    id: 'SH_SYSTEM_FILES_WRITE', sev: 'high', cat: 'shell', review: true,
    re: /(>>?\s*|\btee\s+(-a\s+)?|\bsed\s+-i[^\n]*\s)\/etc\/(hosts|resolv\.conf|passwd|shadow|sudoers|group)\b/,
    title: 'Modification de fichiers système (hosts, resolv.conf, passwd, sudoers)',
    desc: 'Redirection DNS, ajout d\'utilisateur ou de droits sudo.',
    fix: 'Supprimer : utiliser la configuration Kubernetes (hostAliases, dnsConfig) si nécessaire et documenté.',
  },
  {
    id: 'SH_INLINE_INTERPRETER', sev: 'high', cat: 'shell', review: true,
    re: /\bnode\s+(-e|--eval|-p|--print)\s|\bpython[23]?\s+-c\s|\bperl\s+-e\s|\bruby\s+-e\s|\bphp\s+-r\s/,
    title: 'Code exécuté en ligne (node -e, python -c…)',
    desc: 'Du code est passé directement en argument : moyen discret d\'exécuter une charge.',
    fix: 'Lire le code exécuté et le déplacer dans un fichier versionné relu.',
  },
  {
    id: 'SH_POWERSHELL_DOWNLOAD', sev: 'high', cat: 'shell',
    re: /-(w|WindowStyle)\s+hidden|DownloadString\s*\(|DownloadFile\s*\(|Net\.WebClient|Start-BitsTransfer|bitsadmin\s+\/transfer|certutil\s+[^\n]*-urlcache/i,
    title: 'Téléchargement ou exécution furtive PowerShell / Windows',
    desc: 'Techniques classiques de téléchargement de charge sous Windows (LOLBins).',
    fix: 'Supprimer et investiguer.',
  },
  {
    id: 'SH_ENV_EXFIL', sev: 'high', cat: 'shell',
    re: /\b(env|printenv|set)\b\s*\|\s*(curl|wget|nc|base64)|\b(curl|wget)\b[^\n]*(-d|--data[\w-]*|--post-data)[^\n]*\$\(\s*(env|printenv|cat\s+[^\n]*(\.npmrc|\.env|id_rsa|credentials))/i,
    title: 'Exfiltration de variables d\'environnement ou de fichiers d\'identifiants',
    desc: 'Les variables d\'environnement (tokens CI, secrets) ou des fichiers d\'identifiants sont envoyés vers l\'extérieur.',
    fix: 'Supprimer immédiatement et révoquer les secrets exposés.',
  },
  {
    id: 'SH_TOKEN_SENT', sev: 'high', cat: 'shell', review: true,
    re: /\b(curl|wget)\b[^\n]*\$\{?(CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|GITLAB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|AWS_SECRET_ACCESS_KEY|[A-Z_]*(TOKEN|SECRET|PASSWORD))\b/,
    title: 'Token ou secret transmis dans une requête réseau',
    desc: 'Un secret est envoyé dans une requête : vérifier que la destination est légitime.',
    fix: 'Vérifier l\'hôte de destination ; un token CI ne doit être envoyé qu\'à l\'instance GitLab ou au registre interne.',
  },
  {
    id: 'SH_NPM_REGISTRY_CHANGE', sev: 'medium', cat: 'shell', review: true,
    re: /\b(npm|yarn|pnpm)\s+config\s+set\s+(registry|script-shell|node-options|ignore-scripts\s+false|@[\w-]+:registry)|\s--registry[= ]\S+/,
    title: 'Changement de registre ou de configuration npm en ligne de commande',
    desc: 'Modifier le registre permet d\'installer des paquets depuis une source non maîtrisée ; script-shell / node-options permettent d\'injecter du code.',
    fix: 'Utiliser uniquement le registre Artifactory d\'entreprise.',
  },
  ...NET_RULES.map(r => Object.assign({}, r, { cat: 'shell' })),
];

module.exports = { SHELL_RULES, NET_RULES, SUSPICIOUS_DOMAINS_RE, isInternalHost, isIp, hostOf };
