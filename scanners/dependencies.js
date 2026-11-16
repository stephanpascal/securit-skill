'use strict';
const crypto = require('crypto');
const { makeFinding } = require('../lib/finding');
const { scanLines, scanText } = require('../lib/patterns');
const { SHELL_RULES } = require('../lib/shell-rules');
const { typosquatTarget } = require('../lib/typosquat');
const { request, getJson } = require('../lib/net');
const { extractTgz } = require('../lib/tar');
const { truncate } = require('../lib/util');
const sourceCode = require('./source-code');

const D = 'dependances';
const R = {
  INSTALL_KNOWN: { id: 'DEP_SCRIPT_INSTALLATION_CONNU', sev: 'low', title: 'Dépendance avec script d\'installation (paquet connu)', desc: 'Ce paquet exécute un script à l\'installation, ce qui est habituel pour lui (compilation native, téléchargement de binaire, message).', fix: 'Acceptable ; envisager "npm ci --ignore-scripts" puis "npm rebuild <paquet>" pour les seuls paquets nécessaires.' },
  INSTALL_UNKNOWN: { id: 'DEP_SCRIPT_INSTALLATION', sev: 'high', review: true, title: 'Dépendance exécutant un script à l\'installation', desc: 'Ce paquet (direct ou transitif) exécute du code lors de "npm install" : c\'est le vecteur principal des attaques de la chaîne d\'approvisionnement npm.', fix: 'Vérifier le script (détail ci-dessous si l\'archive a pu être inspectée) ; utiliser --ignore-scripts.' },
  INSTALL_MALICIOUS: { id: 'DEP_SCRIPT_INSTALLATION_DANGEREUX', sev: 'critical', title: 'Script d\'installation d\'une dépendance contenant un motif dangereux', desc: 'Le script exécuté à l\'installation contient un motif malveillant (téléchargement exécuté, exfiltration, obfuscation…).', fix: 'Retirer la dépendance, ne pas lancer npm install sans --ignore-scripts, investiguer les postes qui l\'ont installée.' },
  RESOLVED: { id: 'DEP_SOURCE_NON_AUTORISEE', sev: 'high', title: 'Dépendance téléchargée depuis une source non autorisée', desc: 'Le lockfile indique une URL de téléchargement hors des registres autorisés.', fix: 'Régénérer le lockfile depuis Artifactory et vérifier pourquoi cette source apparaît.' },
  RESOLVED_GIT: { id: 'DEP_SOURCE_GIT_OU_URL', sev: 'high', review: true, title: 'Dépendance transitive provenant de git ou d\'une URL', desc: 'Contenu non immuable, hors registre.', fix: 'Remplacer par une version publiée.' },
  INTERNAL_PUBLIC: { id: 'DEP_CONFUSION_DEPENDANCE', sev: 'critical', title: 'Paquet interne résolu depuis le registre public (confusion de dépendances)', desc: 'Un paquet du scope interne a été téléchargé depuis registry.npmjs.org : un attaquant a pu publier un paquet du même nom.', fix: 'Configurer le scope interne vers Artifactory dans .npmrc et régénérer le lockfile.' },
  INTERNAL_EXISTS_PUBLIC: { id: 'DEP_NOM_INTERNE_PUBLIC', sev: 'high', review: true, title: 'Nom de paquet interne existant sur le registre public', desc: 'Un paquet interne non scopé porte un nom qui existe sur npmjs : risque de confusion de dépendances.', fix: 'Renommer avec un scope interne (@entreprise/…).' },
  NO_INTEGRITY: { id: 'DEP_INTEGRITE_ABSENTE', sev: 'medium', title: 'Empreinte d\'intégrité absente dans le lockfile', desc: 'Sans champ integrity, une archive modifiée sur le registre ne serait pas détectée.', fix: 'Régénérer le lockfile.' },
  SHA1: { id: 'DEP_INTEGRITE_SHA1', sev: 'low', title: 'Empreinte d\'intégrité SHA-1 uniquement', desc: 'SHA-1 est obsolète.', fix: 'Régénérer le lockfile avec une version récente de npm.' },
  INTEGRITY_MISMATCH: { id: 'DEP_INTEGRITE_DIFFERENTE', sev: 'critical', title: 'L\'archive téléchargée ne correspond pas à l\'empreinte du lockfile', desc: 'Le contenu servi par le registre diffère de celui enregistré dans le lockfile : altération possible.', fix: 'Ne pas installer ; investiguer le registre et le lockfile.' },
  TYPO: { id: 'DEP_TYPOSQUATTING', sev: 'high', review: true, title: 'Dépendance transitive au nom proche d\'un paquet populaire', desc: 'Possible typosquatting dans l\'arbre de dépendances.', fix: 'Identifier quel paquet l\'introduit (npm ls <nom>) et vérifier l\'éditeur.' },
  LOCK_STALE: { id: 'DEP_LOCKFILE_DESYNCHRONISE', sev: 'medium', title: 'Dépendance du package.json absente du lockfile', desc: 'Le lockfile n\'est pas à jour : l\'installation résoudra des versions non auditées.', fix: 'Lancer npm install --package-lock-only --ignore-scripts et versionner le résultat.' },
  MALWARE: { id: 'DEP_PAQUET_MALVEILLANT_CONNU', sev: 'critical', title: 'Paquet malveillant connu (base OSV / OpenSSF)', desc: 'Cette version est répertoriée comme malveillante.', fix: 'Retirer immédiatement, considérer les postes et la CI ayant installé ce paquet comme compromis, révoquer les secrets.' },
  VULN: { id: 'DEP_VULNERABILITE', sev: 'medium', title: 'Vulnérabilité connue (CVE / GHSA)', desc: 'Cette version présente des vulnérabilités publiées.', fix: 'Mettre à jour vers une version corrigée.' },
  RECENT: { id: 'DEP_VERSION_TRES_RECENTE', sev: 'high', review: true, title: 'Version publiée très récemment', desc: 'Les versions piégées sont généralement détectées et retirées en quelques jours ; une version très récente n\'a pas encore ce recul.', fix: 'Attendre quelques jours ou figer la version précédente ; vérifier le changelog.' },
  NEW_PKG: { id: 'DEP_PAQUET_TRES_RECENT', sev: 'high', review: true, title: 'Paquet créé très récemment', desc: 'Un paquet tout juste créé est un signal fort de typosquatting ou de paquet piégé.', fix: 'Vérifier l\'éditeur et le besoin.' },
  NATIVE: { id: 'DEP_COMPILATION_NATIVE', sev: 'low', review: true, title: 'Dépendance avec compilation native (binding.gyp)', desc: 'npm exécute implicitement node-gyp (donc du code) à l\'installation, même sans script déclaré.', fix: 'Vérifier le besoin.' },
  LOCK_INCOHERENT: { id: 'DEP_LOCKFILE_INCOHERENT', sev: 'high', title: 'Lockfile incohérent : l\'archive téléchargée ne correspond pas au paquet déclaré', desc: 'L\'URL "resolved" pointe vers l\'archive d\'un autre paquet ou d\'une autre version (injection dans le lockfile, difficile à repérer en relecture de MR).', fix: 'Régénérer le lockfile (npm install --package-lock-only --ignore-scripts) et identifier le commit qui l\'a modifié.' },
  IOC_VERSION: { id: 'DEP_VERSION_COMPROMISE_CONNUE', sev: 'critical', title: 'Version de paquet connue comme compromise (IOC)', desc: 'Cette version figure dans la liste des versions piégées connues (rules/ioc.json : Shai-Hulud, chalk/debug, Nx s1ngularity, event-stream, ua-parser-js…).', fix: 'Changer de version immédiatement ; considérer comme compromis les postes et la CI qui l\'ont installée et révoquer leurs secrets.' },
  NONEXISTENT: { id: 'DEP_PAQUET_INEXISTANT', sev: 'high', review: true, title: 'Dépendance introuvable sur le registre', desc: 'Le nom n\'existe pas (ou plus) sur le registre : nom inventé par une IA (« slopsquatting ») qu\'un attaquant peut enregistrer, paquet retiré pour malveillance, ou paquet privé mal configuré.', fix: 'Vérifier l\'orthographe et l\'origine de cette dépendance.' },
  PUBLISHER_CHANGE: { id: 'DEP_CHANGEMENT_EDITEUR', sev: 'medium', review: true, title: 'Version publiée par un compte inconnu du paquet', desc: 'Cette version a été publiée par un compte qui n\'avait jamais publié ni maintenu ce paquet : signe possible de reprise du paquet ou d\'ajout d\'un mainteneur malveillant.', fix: 'Vérifier le changelog et l\'identité du nouvel éditeur.' },
  PROVENANCE_LOST: { id: 'DEP_PROVENANCE_PERDUE', sev: 'high', review: true, title: 'Perte de l\'attestation de provenance', desc: 'La version précédente était publiée depuis une CI avec attestation de provenance, celle-ci ne l\'est plus : publication manuelle possible avec un token volé (cas des compromissions de 2025).', fix: 'Vérifier cette version (diff avec la précédente) ou rester sur la précédente.' },
  MANIFEST_MISMATCH: { id: 'DEP_MANIFESTE_DIFFERENT', sev: 'high', title: 'Scripts d\'installation différents entre le registre et l\'archive (manifest confusion)', desc: 'Les métadonnées affichées par le registre ne reflètent pas le package.json réellement contenu dans l\'archive installée.', fix: 'Se fier à l\'archive : relire son script et envisager de retirer la dépendance.' },
};
const IOC_PAQUETS = require('../rules/ioc.json').paquets || {};
for (const r of Object.values(R)) r.cat = D;

// Paquets connus pour avoir un script d'installation légitime
const KNOWN_INSTALL = new Set(['esbuild', '@esbuild/linux-x64', 'fsevents', 'node-sass', 'sass-embedded', 'sharp', 'canvas', 'bcrypt', 'sqlite3', 'better-sqlite3', 'bufferutil', 'utf-8-validate', 'core-js', 'core-js-pure', 'protobufjs', 'puppeteer', 'cypress', 'nx', '@nrwl/cli', '@swc/core', 'lmdb', 'msgpackr-extract', 'nice-napi', 'deasync', '@nestjs/core', 'es5-ext', 'husky', 'node-gyp', 'grpc', '@grpc/grpc-js', 'electron', 'playwright', 'playwright-core', '@parcel/watcher', 'unrs-resolver', 'iltorb', 'ffi-napi', 'ref-napi', 'kerberos', 'snappy', 'zeromq', 'argon2', 'cpu-features', 'ssh2', 'dtrace-provider', 'spawn-sync', 'ejs', 'styled-components', 'aws-sdk', 'yarn', 'pnpm', 'vue-demi', 'ngx-build-plus', 'node-pty', 'keytar', 'leveldown', 'farmhash', '@sentry/cli', 'phantomjs-prebuilt', 'chromedriver', 'geckodriver', 'edgedriver', 'gifsicle', 'mozjpeg', 'optipng-bin', 'pngquant-bin', 'cwebp-bin', 'jpegtran-bin', 'highlight.js', 'web3', 'oracledb', 'ibm_db', 'couchbase', 'nodegit', 'robotjs', 'uws', 'microtime', 'heapdump', 'v8-profiler-next', 'appium-chromedriver', '@prisma/client', 'prisma', '@prisma/engines', 'lefthook', 'simple-git-hooks', 'patch-package', 'opencollective-postinstall', 'protoc', 'grpc-tools', 'nodemon', 'turbo', '@biomejs/biome', '@tailwindcss/oxide', 'lightningcss', '@rollup/rollup-linux-x64-gnu']);

function parseLock(json) {
  const out = [];
  if (json.packages) {
    for (const [key, v] of Object.entries(json.packages)) {
      if (key === '') continue;
      const name = v.name || key.slice(key.lastIndexOf('node_modules/') + 13);
      out.push({ name, version: v.version, resolved: v.resolved, integrity: v.integrity, hasInstallScript: !!v.hasInstallScript, dev: !!v.dev, link: !!v.link, path: key, direct: !key.slice(13).includes('node_modules/') && key.startsWith('node_modules/') });
    }
  } else if (json.dependencies) {
    const walk = (deps, prefix, depth) => {
      for (const [name, v] of Object.entries(deps || {})) {
        out.push({ name, version: v.version, resolved: v.resolved, integrity: v.integrity, hasInstallScript: false, dev: !!v.dev, path: prefix + 'node_modules/' + name, direct: depth === 0, v1: true });
        if (v.dependencies) walk(v.dependencies, prefix + 'node_modules/' + name + '/', depth + 1);
      }
    };
    walk(json.dependencies, '', 0);
  }
  return out;
}

function encName(n) { return n.startsWith('@') ? '@' + encodeURIComponent(n.slice(1)) : encodeURIComponent(n); }

function hostOfUrl(u) { try { return new URL(u).host.toLowerCase(); } catch { return ''; } }

/** Le token Artifactory n'est envoyé qu'à l'hôte Artifactory configuré (comparaison exacte de l'hôte), en HTTPS. */
function authHeaders(ctx, url) {
  const tok = process.env[ctx.config.npm.tokenEnv || 'NPM_TOKEN'];
  const reg = ctx.config.npm.artifactoryUrl;
  if (tok && reg && /^https:/i.test(url) && hostOfUrl(url) === hostOfUrl(reg)) return { Authorization: 'Bearer ' + tok };
  return {};
}

/** Paquet interne : ne doit jamais être envoyé à un service public (OSV, registre npm public). */
function isInternal(name, ctx) {
  const scopes = ctx.config.npm.scopesInternes || [];
  return scopes.some(s => name.startsWith(String(s).replace(/\/$/, '') + '/')) || (ctx.config.npm.paquetsInternesNonScopes || []).includes(name);
}

/** Seuls les registres autorisés sont contactés : l'URL "resolved" du lockfile (contrôlée par le dépôt analysé) n'est jamais appelée telle quelle si elle pointe ailleurs. */
function tarballUrl(dep, ctx) {
  const r = dep.resolved || '';
  if (/^https:\/\//i.test(r) && ctx.config.npm.registresAutorises.some(a => hostOfUrl(r) === hostOfUrl(a) && r.startsWith(a.replace(/\/api\/npm\/[^/]+\/$/, '/')))) return r;
  return `${ctx.config.npm.registreRequetes}${dep.name}/-/${dep.name.split('/').pop()}-${dep.version}.tgz`;
}

function verifyIntegrity(buf, integrity) {
  if (!integrity) return null;
  const [algo, b64] = integrity.split(' ')[0].split('-');
  if (!['sha512', 'sha384', 'sha256', 'sha1'].includes(algo)) return null;
  return crypto.createHash(algo).update(buf).digest('base64') === b64;
}

/** Télécharge et inspecte l'archive d'une dépendance ayant un script d'installation. Rien n'est exécuté. */
async function inspectTarball(dep, ctx) {
  const url = tarballUrl(dep, ctx);
  if (isInternal(dep.name, ctx) && !ctx.config.npm.artifactoryUrl) throw new Error('paquet interne : non téléchargé depuis le registre public');
  const res = await request(url, { headers: Object.assign({ Accept: '*/*' }, authHeaders(ctx, url)), timeout: 30000, maxBytes: 60 * 1024 * 1024 });
  if (res.status !== 200) throw new Error('HTTP ' + res.status);
  const integrityOk = verifyIntegrity(res.body, dep.integrity);
  const entries = extractTgz(res.body, { filter: n => /\.(js|cjs|mjs|json|sh|gyp)$/.test(n) || !n.includes('.') });
  const byName = new Map(entries.map(e => [e.name.replace(/^[^/]+\//, ''), e]));
  const pj = byName.get('package.json');
  let scripts = {};
  try { scripts = JSON.parse(pj.content.toString('utf8')).scripts || {}; } catch { /* ignore */ }
  const hooks = Object.entries(scripts).filter(([k]) => ['preinstall', 'install', 'postinstall'].includes(k));
  if (!hooks.length && byName.has('binding.gyp')) hooks.push(['install (implicite)', 'node-gyp rebuild']);
  const files = [];
  const addFile = p => {
    p = p.replace(/^\.\//, '').replace(/^["']|["']$/g, '');
    const e = byName.get(p) || byName.get(p + '.js') || byName.get(p + '/index.js');
    if (e && e.content && !files.some(f => f.name === p)) files.push({ name: p, text: e.content.toString('utf8') });
  };
  for (const [, cmd] of hooks) {
    const m = /\bnode\s+([^\s&|;]+\.(c|m)?js)\b/.exec(cmd) || /\bnode\s+([^\s&|;-][^\s&|;]*)/.exec(cmd);
    if (m) addFile(m[1]);
    // node -e "require('./postinstall')" : on suit le fichier requis
    for (const r of cmd.matchAll(/require\(\s*\\?["']([^"'\\]+)\\?["']\s*\)/g)) addFile(r[1]);
  }
  return { url, integrityOk, hooks, files };
}

module.exports = {
  id: 'dependencies',
  label: 'Dépendances (lockfile)',
  category: D,
  controls: [
    'Lecture statique de package-lock.json (aucune installation) : toutes les dépendances directes et transitives',
    'Dépendances avec script d\'installation (hasInstallScript) — paquets connus vs inconnus',
    'Sources de téléchargement hors registres autorisés (Artifactory), git, URL ; confusion de dépendances (scopes internes)',
    'Empreintes d\'intégrité absentes ou SHA-1 ; lockfile désynchronisé du package.json',
    'Typosquatting sur l\'ensemble de l\'arbre',
    'En ligne : téléchargement des archives à script d\'installation (sans exécution), vérification de l\'empreinte, analyse du script et du fichier JS appelé',
    'En ligne : vulnérabilités et paquets malveillants connus (OSV.dev, incluant la base OpenSSF malicious-packages)',
    'En ligne : dates de publication (version ou paquet très récents), paquets introuvables (slopsquatting)',
    'En ligne : changement de compte éditeur et perte d\'attestation de provenance par rapport à la version précédente',
    'En ligne : scripts d\'installation différents entre registre et archive (manifest confusion)',
    'Cohérence nom/version entre chaque entrée du lockfile et l\'archive téléchargée (injection de lockfile)',
    'Versions compromises connues, hors ligne (rules/ioc.json : Shai-Hulud, chalk/debug, Nx, event-stream…)',
    'Dépendances distantes en HTTP non chiffré (critique)',
  ],
  parseLock,
  inspectTarball,
  tarballUrl,
  authHeaders,
  isInternal,
  async run(ctx) {
    const findings = [];
    const notes = [];
    const installScripts = [];
    let status = 'ok';
    const lockFile = ctx.files.find(f => f.rel === 'package-lock.json') || ctx.files.find(f => f.rel === 'npm-shrinkwrap.json') || ctx.files.find(f => f.base === 'package-lock.json' && !f.rel.includes('node_modules'));
    if (!lockFile) {
      let hasDeps = false;
      for (const f of ctx.files.filter(x => x.base === 'package.json')) { try { const j = JSON.parse(ctx.readText(f) || '{}'); if (Object.keys(Object.assign({}, j.dependencies, j.devDependencies)).length) hasDeps = true; } catch { /* ignore */ } }
      return { findings, filesAnalyzed: 0, status: hasDeps ? 'partiel' : 'non applicable', notes: [hasDeps ? 'Aucun package-lock.json : analyse des dépendances transitives impossible.' : 'Aucune dépendance npm déclarée.'] };
    }
    let lock;
    try { lock = JSON.parse(ctx.readText(lockFile) || ''); } catch { return { findings, filesAnalyzed: 1, status: 'erreur', notes: ['package-lock.json illisible.'] }; }
    const deps = parseLock(lock);
    if (deps.some(d => d.v1)) notes.push('Lockfile v1 : l\'indicateur hasInstallScript n\'existe pas, les scripts d\'installation ne sont détectés qu\'en ligne.');
    const allowed = ctx.config.npm.registresAutorises;
    const internalScopes = ctx.config.npm.scopesInternes || [];
    const at = (rule, dep, data) => findings.push(makeFinding(rule, Object.assign({ file: lockFile.rel, evidence: `${dep.name}@${dep.version}${dep.dev ? ' (dev)' : ''}` }, data)));

    for (const dep of deps) {
      if (dep.link) continue;
      const r = dep.resolved || '';
      if (r) {
        if (/^(git\+|git:|github:|ssh:)/.test(r) || (/^https?:/.test(r) && !/\.tgz(\?|$)/.test(r))) at(R.RESOLVED_GIT, dep, { evidence: `${dep.name}@${dep.version} ← ${truncate(r, 150)}` });
        else if (/^https?:/.test(r) && !allowed.some(a => r.startsWith(a) || r.startsWith(a.replace(/\/api\/npm\/[^/]+\/$/, '/')))) at(R.RESOLVED, dep, { evidence: `${dep.name}@${dep.version} ← ${truncate(r, 150)}`, severity: /^http:/i.test(r) ? 'critical' : 'high' });
        if (internalScopes.some(s => dep.name.startsWith(s + '/')) && r.includes('registry.npmjs.org')) at(R.INTERNAL_PUBLIC, dep, { evidence: `${dep.name}@${dep.version} ← ${r}` });
        // Cohérence nom/version ↔ archive (format registre : …/<nom>/-/<base>-<version>.tgz)
        const tm = /\/((?:@[^/]+\/)?[^/]+)\/-\/([^/]+?)-(\d[^/]*)\.tgz(?:\?|$)/.exec(r.replace(/%2f/gi, '/'));
        if (tm && dep.version && (tm[1] !== dep.name || tm[3] !== dep.version)) {
          at(R.LOCK_INCOHERENT, dep, { evidence: `${dep.name}@${dep.version} (${dep.path}) ← archive de ${tm[1]}@${tm[3]}` });
        }
      }
      if (IOC_PAQUETS[dep.name] && IOC_PAQUETS[dep.name].includes(dep.version)) at(R.IOC_VERSION, dep, { evidence: `${dep.name}@${dep.version} — ${dep.path}` });
      if (r && /^https?:/.test(r)) {
        if (!dep.integrity) at(R.NO_INTEGRITY, dep);
        else if (/^sha1-/.test(dep.integrity)) at(R.SHA1, dep);
      }
      if (!dep.direct) {
        const t = typosquatTarget(dep.name);
        if (t) at(R.TYPO, dep, { description: `${R.TYPO.desc} « ${dep.name} » ressemble à « ${t} ».` });
      }
      if (dep.hasInstallScript) {
        const known = KNOWN_INSTALL.has(dep.name) || /^@(esbuild|swc|rollup|parcel|img|biomejs|nx|nrwl|sentry|prisma)\//.test(dep.name);
        installScripts.push({ paquet: dep.name, version: dep.version, connu: known, dev: dep.dev, chemin: dep.path });
      }
    }
    // agrégation : faible bruit pour les paquets connus
    const known = installScripts.filter(i => i.connu);
    if (known.length) findings.push(makeFinding(R.INSTALL_KNOWN, { file: lockFile.rel, evidence: known.map(i => `${i.paquet}@${i.version}`).join(', '), extra: { paquets: known.length } }));

    // package.json ↔ lockfile
    const rootPkg = ctx.files.find(f => f.rel === lockFile.rel.replace(/(package-lock|npm-shrinkwrap)\.json$/, 'package.json'));
    if (rootPkg) {
      try {
        const pkg = JSON.parse(ctx.readText(rootPkg));
        const names = new Set(deps.filter(d => d.direct).map(d => d.name));
        const missing = Object.keys(Object.assign({}, pkg.dependencies, pkg.devDependencies)).filter(n => !names.has(n));
        if (missing.length && names.size) findings.push(makeFinding(R.LOCK_STALE, { file: lockFile.rel, evidence: missing.slice(0, 10).join(', ') + (missing.length > 10 ? ` (+${missing.length - 10})` : '') }));
      } catch { /* ignore */ }
    }

    // ---- En ligne ----
    const online = !ctx.offline;
    const unknown = installScripts.filter(i => !i.connu);
    const inspected = new Map();
    if (online && ctx.config.enLigne.inspecterArchives && ctx.network.registre) {
      for (const i of unknown.slice(0, ctx.config.enLigne.maxArchives)) {
        const dep = deps.find(d => d.name === i.paquet && d.version === i.version);
        try { inspected.set(i.paquet + '@' + i.version, await inspectTarball(dep, ctx)); }
        catch (e) { inspected.set(i.paquet + '@' + i.version, { error: e.message }); }
      }
      if (unknown.length > ctx.config.enLigne.maxArchives) notes.push(`${unknown.length - ctx.config.enLigne.maxArchives} archives non inspectées (limite enLigne.maxArchives).`);
    } else if (unknown.length) {
      notes.push('Archives des dépendances à script d\'installation non inspectées (hors ligne ou registre inaccessible).');
      status = 'partiel';
    }
    for (const i of unknown) {
      const key = i.paquet + '@' + i.version;
      const ins = inspected.get(key);
      const base = { file: lockFile.rel, evidence: `${key}${i.dev ? ' (dev)' : ''} — ${i.chemin}` };
      if (!ins || ins.error) {
        findings.push(makeFinding(R.INSTALL_UNKNOWN, Object.assign(base, ins && ins.error ? { description: R.INSTALL_UNKNOWN.desc + ` (inspection impossible : ${ins.error})` } : {})));
        continue;
      }
      if (ins.integrityOk === false) findings.push(makeFinding(R.INTEGRITY_MISMATCH, base));
      const cmdText = ins.hooks.map(([k, v]) => `${k}: ${v}`).join(' | ');
      const danger = [];
      // "node -e" seul n'est pas un motif dangereux ici (enveloppe courante) : c'est le code exécuté qui est analysé.
      for (const [k, v] of ins.hooks) danger.push(...scanLines([{ n: 1, text: v }], SHELL_RULES, { file: `${key} (script ${k})`, category: D }).filter(x => x.rule !== 'SH_INLINE_INTERPRETER'));
      for (const f of ins.files) danger.push(...scanText(f.text, sourceCode.MINIFIED_RULES.concat(SHELL_RULES), { file: `${key}/${f.name}`, category: D, maxPerRule: 2 }).filter(x => ['critical', 'high'].includes(x.severity)));
      if (danger.length) {
        findings.push(makeFinding(R.INSTALL_MALICIOUS, Object.assign(base, { evidence: `${key} — ${truncate(cmdText, 150)} — motifs : ${[...new Set(danger.map(d => d.title))].slice(0, 4).join(' ; ')}` })));
        findings.push(...danger.map(d => Object.assign(d, { category: D, severity: d.severity === 'high' ? 'high' : d.severity })));
      } else {
        const isNative = ins.hooks.every(([, v]) => /^(node-gyp(-build)?( rebuild)?|prebuild-install( \|\| node-gyp rebuild)?.*|node-pre-gyp install.*)$/.test(v.trim()));
        findings.push(makeFinding(isNative ? R.NATIVE : R.INSTALL_UNKNOWN, Object.assign(base, { evidence: `${key} — ${truncate(cmdText, 200) || '(aucun script trouvé dans l\'archive)'}`, severity: isNative ? 'low' : 'medium', description: (isNative ? R.NATIVE.desc : R.INSTALL_UNKNOWN.desc) + ' Archive inspectée : aucun motif dangereux détecté automatiquement.' })));
      }
    }

    // OSV
    if (online && ctx.config.enLigne.osv && ctx.network.osv) {
      try {
        // Seuls des noms de paquets publics + versions sont envoyés à OSV (jamais les paquets internes, ni le code).
        const uniq = [...new Map(deps.filter(d => d.version && !d.link && !isInternal(d.name, ctx) && !/^(file:|git|link:)/.test(d.resolved || '')).map(d => [d.name + '@' + d.version, d])).values()];
        const vulnsByPkg = new Map();
        for (let i = 0; i < uniq.length; i += 500) {
          const chunk = uniq.slice(i, i + 500);
          const r = await getJson('https://api.osv.dev/v1/querybatch', { method: 'POST', body: { queries: chunk.map(d => ({ package: { name: d.name, ecosystem: 'npm' }, version: d.version })) }, timeout: 60000 });
          (r.json && r.json.results || []).forEach((res, idx) => { if (res.vulns && res.vulns.length) vulnsByPkg.set(chunk[idx].name + '@' + chunk[idx].version, res.vulns.map(v => v.id)); });
        }
        const ids = [...new Set([].concat(...vulnsByPkg.values()))];
        const details = new Map();
        let budget = ctx.config.enLigne.maxRequetes;
        for (const id of ids) {
          if (budget-- <= 0) break;
          try { const r = await getJson('https://api.osv.dev/v1/vulns/' + encodeURIComponent(id), { timeout: 15000 }); if (r.json) details.set(id, r.json); } catch { /* ignore */ }
        }
        const sevMap = { CRITICAL: 'high', HIGH: 'medium', MODERATE: 'low', MEDIUM: 'low', LOW: 'info' };
        for (const [key, list] of vulnsByPkg) {
          const mal = list.filter(id => id.startsWith('MAL-'));
          if (mal.length) findings.push(makeFinding(R.MALWARE, { file: lockFile.rel, evidence: `${key} — ${mal.join(', ')}` }));
          const vul = list.filter(id => !id.startsWith('MAL-'));
          if (!vul.length) continue;
          let worst = 'info';
          const labels = vul.map(id => {
            const d = details.get(id);
            const s = d && d.database_specific && d.database_specific.severity ? String(d.database_specific.severity).toUpperCase() : null;
            const mapped = s ? (sevMap[s] || 'low') : 'low';
            if (['high', 'medium', 'low', 'info'].indexOf(mapped) < ['high', 'medium', 'low', 'info'].indexOf(worst)) worst = mapped;
            const alias = d && (d.aliases || []).find(a => a.startsWith('CVE-'));
            return `${id}${alias ? ' / ' + alias : ''}${s ? ' (' + s + ')' : ''}`;
          });
          findings.push(makeFinding(R.VULN, { file: lockFile.rel, severity: worst, evidence: `${key} — ${labels.slice(0, 6).join(', ')}${labels.length > 6 ? ` (+${labels.length - 6})` : ''}` }));
        }
        if (ids.length > ctx.config.enLigne.maxRequetes) notes.push('Sévérité inconnue pour une partie des vulnérabilités (limite enLigne.maxRequetes).');
      } catch (e) { notes.push('Requête OSV échouée : ' + e.message); status = 'partiel'; }
    } else if (ctx.config.enLigne.osv) {
      notes.push('Vulnérabilités connues (OSV) non vérifiées : hors ligne ou api.osv.dev inaccessible.');
      status = 'partiel';
    }

    // Dates de publication (dépendances directes + scripts d'installation)
    if (online && ctx.config.enLigne.datesPublication && ctx.network.registre) {
      const publicRegistry = !ctx.config.npm.artifactoryUrl;
      const targets = [...new Map(deps.filter(d => (d.direct || d.hasInstallScript) && d.version && !d.link && !(publicRegistry && isInternal(d.name, ctx))).map(d => [d.name, d])).values()].slice(0, Math.floor(ctx.config.enLigne.maxRequetes / 2));
      const limitDays = ctx.config.enLigne.joursVersionRecente;
      const now = Date.now();
      for (const dep of targets) {
        try {
          const url = ctx.config.npm.registreRequetes + encName(dep.name);
          const r = await getJson(url, { headers: authHeaders(ctx, url), timeout: 20000, maxBytes: 40 * 1024 * 1024 });
          if (r.status === 404) { if (!isInternal(dep.name, ctx)) at(R.NONEXISTENT, dep, { evidence: `${dep.name}@${dep.version} : introuvable sur ${hostOfUrl(url)}` }); continue; }
          if (!r.json || !r.json.time) continue;
          const pub = r.json.time[dep.version];
          if (pub && now - Date.parse(pub) < limitDays * 86400000) at(R.RECENT, dep, { evidence: `${dep.name}@${dep.version} publiée le ${pub.slice(0, 10)}` });
          const created = r.json.time.created;
          if (created && now - Date.parse(created) < 30 * 86400000) at(R.NEW_PKG, dep, { evidence: `${dep.name} créé le ${created.slice(0, 10)}` });
          // Version précédente (par date de publication) : éditeur et provenance
          const versions = r.json.versions || {};
          const cur = versions[dep.version];
          if (cur && pub) {
            const prevVer = Object.keys(versions).filter(v => v !== dep.version && r.json.time[v] && r.json.time[v] < pub && !/-/.test(v)).sort((a, b) => r.json.time[b].localeCompare(r.json.time[a]))[0];
            const prev = prevVer && versions[prevVer];
            if (prev) {
              const who = v => (v && v._npmUser && (v._npmUser.name || v._npmUser.email)) || null;
              // Signal retenu : un compte qui n'a jamais publié ni maintenu ce paquet auparavant
              // (les projets à plusieurs mainteneurs qui publient à tour de rôle ne sont pas signalés).
              const known = new Set();
              for (const [v, meta] of Object.entries(versions)) {
                if (v === dep.version || !r.json.time[v] || r.json.time[v] >= pub) continue;
                if (who(meta)) known.add(who(meta));
                for (const m of (meta.maintainers || [])) if (m && m.name) known.add(m.name);
              }
              // Seules les versions récentes (< 180 jours) sont signalées : une reprise ancienne aurait déjà été détectée.
              const ageDays = (now - Date.parse(pub)) / 86400000;
              if (ageDays < 180 && who(cur) && known.size && !known.has(who(cur))) at(R.PUBLISHER_CHANGE, dep, { evidence: `${dep.name}@${dep.version} (publiée le ${pub.slice(0, 10)}) par « ${who(cur)} », jamais vu sur les versions précédentes (dernière : ${prevVer} par « ${who(prev) || '?'} »)`, severity: ageDays < 60 ? 'high' : 'medium' });
              const att = v => !!(v.dist && v.dist.attestations);
              if (att(prev) && !att(cur)) at(R.PROVENANCE_LOST, dep, { evidence: `${dep.name}@${prevVer} avait une attestation de provenance, ${dep.version} n'en a pas` });
            }
            // Manifest confusion : scripts d'installation du registre vs archive inspectée
            const ins = inspected.get(dep.name + '@' + dep.version);
            if (ins && ins.hooks && !ins.error) {
              const regHooks = Object.entries(cur.scripts || {}).filter(([k]) => ['preinstall', 'install', 'postinstall'].includes(k)).map(([k, v]) => `${k}: ${v}`).sort().join(' | ');
              const tgzHooks = ins.hooks.filter(([k]) => !/implicite/.test(k)).map(([k, v]) => `${k}: ${v}`).sort().join(' | ');
              if (regHooks !== tgzHooks) at(R.MANIFEST_MISMATCH, dep, { evidence: `${dep.name}@${dep.version} — registre : « ${truncate(regHooks || 'aucun', 100)} » / archive : « ${truncate(tgzHooks || 'aucun', 100)} »` });
            }
          }
        } catch { /* ignore */ }
      }
      // Noms internes non scopés existants sur le registre public : envoie ces noms à registry.npmjs.org,
      // donc désactivé par défaut (option explicite enLigne.verifierNomsInternesSurNpmPublic).
      for (const n of (ctx.config.enLigne.verifierNomsInternesSurNpmPublic ? (ctx.config.npm.paquetsInternesNonScopes || []) : [])) {
        try {
          const r = await request('https://registry.npmjs.org/' + encName(n), { timeout: 10000, maxBytes: 2 * 1024 * 1024 });
          if (r.status === 200) findings.push(makeFinding(R.INTERNAL_EXISTS_PUBLIC, { file: lockFile.rel, evidence: n }));
        } catch { /* ignore */ }
      }
    }

    return { findings, filesAnalyzed: 1, status, inventory: { dependances: { total: deps.length, directes: deps.filter(d => d.direct).length }, scriptsInstallation: installScripts }, notes };
  },
};
