'use strict';
const { scanText } = require('../lib/patterns');
const { makeFinding } = require('../lib/finding');

const X = 'secrets';
const RULES = [
  { id: 'SECRET_CLE_PRIVEE', sev: 'critical', re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/, title: 'Clé privée dans le dépôt', desc: 'Une clé privée versionnée est compromise : toute personne ayant accès au dépôt (ou à son historique) peut l\'utiliser.', fix: 'Révoquer la clé, la retirer du dépôt ET de l\'historique.' },
  { id: 'SECRET_AWS', sev: 'critical', mask: true, re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, title: 'Clé d\'accès AWS', desc: 'Identifiant de clé AWS.', fix: 'Révoquer la clé et utiliser un gestionnaire de secrets.' },
  { id: 'SECRET_GITLAB', sev: 'critical', mask: true, re: /\b(glpat|gldt|glrt|glptt|glsoat|glcbt|glffct|glimt|glagent)-[0-9A-Za-z_-]{20,}|\bGR1348941[0-9A-Za-z_-]{20,}/, title: 'Token GitLab', desc: 'Token d\'accès GitLab (personnel, déploiement, runner…).', fix: 'Révoquer le token dans GitLab immédiatement.' },
  { id: 'SECRET_GITHUB', sev: 'critical', mask: true, re: /\b(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{60,}/, title: 'Token GitHub', desc: 'Token d\'accès GitHub.', fix: 'Révoquer le token.' },
  { id: 'SECRET_NPM', sev: 'critical', mask: true, re: /\bnpm_[0-9A-Za-z]{36}\b|_authToken\s*=\s*(?!\$\{)[^\s]{10,}|(?<![\w])_auth\s*=\s*(?!\$\{)[A-Za-z0-9+\/=]{10,}|_password\s*=\s*(?!\$\{)\S{6,}/, title: 'Token npm / Artifactory', desc: 'Identifiant du registre npm : permet de publier ou lire des paquets.', fix: 'Révoquer le token, utiliser une variable d\'environnement (${NPM_TOKEN}).' },
  { id: 'SECRET_SLACK', sev: 'high', mask: true, re: /\bxox[abposr]-[0-9A-Za-z-]{10,}|hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]+/, title: 'Token ou webhook Slack', desc: 'Token Slack.', fix: 'Révoquer.' },
  { id: 'SECRET_GOOGLE', sev: 'high', mask: true, re: /\bAIza[0-9A-Za-z_-]{35}\b/, title: 'Clé d\'API Google', desc: 'Clé d\'API Google.', fix: 'Restreindre ou révoquer la clé.' },
  { id: 'SECRET_STRIPE', sev: 'critical', mask: true, re: /\b(sk|rk)_live_[0-9A-Za-z]{20,}/, title: 'Clé secrète Stripe', desc: 'Clé de paiement de production.', fix: 'Révoquer.' },
  { id: 'SECRET_AZURE', sev: 'critical', mask: true, re: /AccountKey=[A-Za-z0-9+\/=]{40,}|SharedAccessSignature=[^;'"\s]{20,}/, title: 'Clé de stockage Azure', desc: 'Chaîne de connexion Azure avec clé.', fix: 'Régénérer la clé.' },
  { id: 'SECRET_JWT', sev: 'medium', review: true, mask: true, re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, title: 'Jeton JWT codé en dur', desc: 'Un jeton JWT versionné peut donner accès à une API.', fix: 'Vérifier s\'il est encore valide et le retirer.' },
  { id: 'SECRET_URL_IDENTIFIANTS', sev: 'high', mask: true, re: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@\/'"<>{}$\[\]]+:[^\s@\/'"<>{}$\[\]]{3,}@[^\s'"]+/i, exclude: /:\/\/(user(name)?|login|admin|test|foo|example)?:(pass(word)?|passwd|pwd|secret|token|changeme|test|bar|example|port|xxx+|\*+)@|:\/\/[^\s]*:(\$\{|\{\{|<|\[|%)|<[\w-]+>|\[[\w-]+\]|%s/i, title: 'Identifiants dans une URL', desc: 'Un identifiant et un mot de passe sont inclus dans une URL.', fix: 'Retirer les identifiants et utiliser un secret.' },
  { id: 'SECRET_GENERIQUE', sev: 'medium', review: true, mask: true, re: /\b(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b['"]?\s*[:=]\s*['"]([^'"\s$\{<]{8,})['"]/i, exclude: /(example|changeme|placeholder|dummy|xxxx|\*\*\*|your[_-]|<|\$\{|\{\{|process\.env|environment\.|i18n|translate|label|placeholder|required|invalid|forgot|confirm)/i, title: 'Valeur ressemblant à un secret', desc: 'Une valeur littérale est affectée à une clé de type mot de passe / token.', fix: 'Vérifier ; déplacer dans un secret Kubernetes ou une variable d\'environnement.' },
].map(r => Object.assign({ cat: X }, r));

const R_FILE = { id: 'SECRET_FICHIER_SENSIBLE', sev: 'high', cat: X, title: 'Fichier sensible versionné', desc: 'Ce type de fichier contient habituellement des secrets (clés, certificats, variables d\'environnement).', fix: 'Retirer du dépôt et de l\'historique, ajouter au .gitignore, révoquer les secrets.' };
const SENSITIVE_FILE = /(^|\/)(\.env(\.(?!example|sample|template|dist|defaults)[\w.-]+)?|id_(rsa|dsa|ecdsa|ed25519)|.*\.(pem|key|p12|pfx|jks|keystore|ppk|kdbx)|\.git-credentials|\.htpasswd|credentials\.json|service-account[\w-]*\.json|\.pgpass|\.netrc)$/i;
const SKIP = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|npm-shrinkwrap\.json)$|\.(map|svg|min\.js)$/i;
const LOCK_SAFE_IDS = new Set(['SECRET_CLE_PRIVEE', 'SECRET_AWS', 'SECRET_GITLAB', 'SECRET_GITHUB', 'SECRET_NPM', 'SECRET_STRIPE']);

module.exports = {
  id: 'secrets',
  label: 'Secrets',
  category: X,
  RULES,
  controls: [
    'Clés privées, tokens GitLab / GitHub / npm / Artifactory, clés AWS / Azure / Google / Stripe / Slack',
    'JWT codés en dur, identifiants dans les URL, valeurs ressemblant à des mots de passe',
    'Fichiers sensibles versionnés (.env, .pem, .key, .p12, keystore, .htpasswd, credentials.json…)',
    'Les valeurs détectées sont masquées dans le rapport',
  ],
  async run(ctx) {
    const findings = [];
    let count = 0;
    const lockRules = RULES.filter(r => LOCK_SAFE_IDS.has(r.id));
    for (const file of ctx.files) {
      if (SENSITIVE_FILE.test(file.rel)) findings.push(makeFinding(R_FILE, { file: file.rel, evidence: file.rel }));
      const text = ctx.readText(file);
      if (!text) continue;
      count++;
      const rules = SKIP.test(file.rel) ? lockRules : RULES;
      const isTest = /\.(spec|test|e2e-spec)\.[cm]?[jt]sx?$|(^|\/)(tests?|__tests__|e2e|cypress|__mocks__|fixtures?)\//.test(file.rel);
      const found = scanText(text, rules, { file: file.rel, category: X, maxPerRule: 3 });
      if (isTest) found.forEach(f => { if (f.rule === 'SECRET_GENERIQUE' || f.rule === 'SECRET_JWT') { f.severity = 'low'; f.description += ' (fichier de test : probablement une valeur factice)'; } });
      findings.push(...found);
    }
    return { findings, filesAnalyzed: count, notes: [] };
  },
};
