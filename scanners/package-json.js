'use strict';
const { scanLines } = require('../lib/patterns');
const { SHELL_RULES } = require('../lib/shell-rules');
const { makeFinding } = require('../lib/finding');
const { typosquatTarget } = require('../lib/typosquat');
const { normalizeRegistry } = require('../lib/config');

const P = 'package';
const R = {
  LIFECYCLE: { id: 'PKG_SCRIPT_INSTALLATION', sev: 'high', review: true, title: 'Script exécuté automatiquement à l\'installation (preinstall/install/postinstall)', desc: 'Ce script s\'exécute sur la machine de quiconque lance "npm install" (poste développeur, CI, build Docker).', fix: 'Supprimer ou justifier ; le code exécuté doit être relu.' },
  PREPARE: { id: 'PKG_SCRIPT_PREPARE', sev: 'low', review: true, title: 'Script "prepare" (exécuté après npm install)', desc: '"prepare" s\'exécute après chaque npm install local (souvent husky install, légitime).', fix: 'Vérifier la commande.' },
  OTHER_HOOK: { id: 'PKG_SCRIPT_CYCLE_DE_VIE', sev: 'medium', review: true, title: 'Script de cycle de vie npm (pre/post)', desc: 'Les scripts pre*/post* s\'exécutent automatiquement avant/après une autre commande npm.', fix: 'Vérifier la commande.' },
  INLINE_NODE: { id: 'PKG_SCRIPT_CODE_EN_LIGNE', sev: 'high', review: true, title: 'Script npm exécutant du code en ligne ou un fichier caché', desc: 'node -e ou un fichier caché/inhabituel est exécuté par un script npm.', fix: 'Lire le code exécuté.' },
  DEP_SOURCE: { id: 'PKG_DEPENDANCE_HORS_REGISTRE', sev: 'high', review: true, title: 'Dépendance installée hors registre (git, URL, fichier)', desc: 'La dépendance ne vient pas du registre : pas de version immuable, contenu modifiable à tout moment par le propriétaire de la source.', fix: 'Publier la dépendance sur Artifactory et la référencer par version.' },
  DEP_WILDCARD: { id: 'PKG_VERSION_NON_BORNEE', sev: 'medium', title: 'Version de dépendance non bornée (*, latest, >=)', desc: 'N\'importe quelle future version (potentiellement compromise) sera installée.', fix: 'Indiquer une version précise ou une plage ^x.y.z, et versionner le lockfile.' },
  TYPO: { id: 'PKG_TYPOSQUATTING', sev: 'high', review: true, title: 'Nom de dépendance proche d\'un paquet populaire (typosquatting)', desc: 'Les attaquants publient des paquets au nom presque identique à un paquet connu.', fix: 'Vérifier l\'orthographe et l\'éditeur du paquet sur le registre.' },
  OVERRIDE_URL: { id: 'PKG_OVERRIDE_HORS_REGISTRE', sev: 'high', title: 'overrides/resolutions vers une source hors registre', desc: 'Une dépendance transitive est forcée vers une source non maîtrisée.', fix: 'Pointer vers une version du registre.' },
  OVERRIDES: { id: 'PKG_OVERRIDES', sev: 'info', review: true, title: 'Dépendances transitives forcées (overrides / resolutions)', desc: 'Des versions de dépendances transitives sont imposées.', fix: 'Vérifier que chaque override est justifié (souvent un correctif de CVE).' },
  PUBLISH: { id: 'PKG_PUBLISHCONFIG', sev: 'medium', review: true, title: 'publishConfig vers un registre non autorisé', desc: 'Le paquet serait publié sur un registre externe.', fix: 'Pointer vers Artifactory.' },
  NO_LOCK: { id: 'PKG_LOCKFILE_ABSENT', sev: 'high', title: 'Lockfile absent', desc: 'Sans package-lock.json, les versions installées changent à chaque installation et les dépendances transitives ne peuvent pas être auditées.', fix: 'Générer et versionner package-lock.json, utiliser "npm ci".' },
  OTHER_LOCK: { id: 'PKG_GESTIONNAIRE_NON_NPM', sev: 'info', title: 'Lockfile yarn/pnpm détecté', desc: 'L\'analyse détaillée des dépendances transitives ne couvre que package-lock.json.', fix: 'Analyse partielle : vérifier manuellement ou convertir en npm.' },
  NPMRC_REG: { id: 'NPMRC_REGISTRE_NON_AUTORISE', sev: 'high', review: true, title: '.npmrc redirige vers un registre non autorisé', desc: 'Les paquets seraient téléchargés depuis une source non maîtrisée (confusion de dépendances, paquets piégés).', fix: 'Utiliser uniquement Artifactory.' },
  NPMRC_DANGER: { id: 'NPMRC_OPTION_DANGEREUSE', sev: 'high', title: 'Option .npmrc dangereuse (script-shell, node-options, onload-script, strict-ssl=false…)', desc: 'Ces options permettent d\'exécuter du code à chaque commande npm ou de désactiver la vérification TLS.', fix: 'Supprimer l\'option.' },
  NPMRC_IGNORE: { id: 'NPMRC_IGNORE_SCRIPTS', sev: 'info', title: 'ignore-scripts activé dans .npmrc', desc: 'Bonne pratique : les scripts d\'installation des dépendances ne sont pas exécutés.', fix: 'Rien à faire.' },
  YARN_PATH: { id: 'YARN_EXECUTABLE_PERSONNALISE', sev: 'high', review: true, title: 'yarnPath / plugin yarn : exécution d\'un fichier JS versionné', desc: 'Yarn exécute le fichier indiqué à chaque commande : un fichier modifié devient une backdoor sur tous les postes.', fix: 'Vérifier l\'intégrité du fichier (comparer à la version officielle).' },
  PNPMFILE: { id: 'PNPMFILE_HOOKS', sev: 'high', review: true, title: '.pnpmfile.cjs : hooks exécutés à l\'installation', desc: 'pnpm exécute ce fichier pendant l\'installation et peut réécrire les dépendances.', fix: 'Relire le fichier.' },
};
for (const r of Object.values(R)) r.cat = P;

const INSTALL_HOOKS = ['preinstall', 'install', 'postinstall', 'preuninstall', 'uninstall', 'postuninstall'];
const NON_REGISTRY = /^(git(\+\w+)?:|github:|gitlab:|bitbucket:|gist:|https?:|file:|link:|portal:)|^[\w-]+\/[\w.-]+(#.*)?$/;

function lineFinder(text) {
  const lines = text.split(/\r?\n/);
  return needle => { const i = lines.findIndex(l => l.includes(needle)); return i >= 0 ? i + 1 : null; };
}

function allowedRegistry(url, ctx) {
  const u = normalizeRegistry(url);
  return ctx.config.npm.registresAutorises.some(r => u.startsWith(r));
}

module.exports = {
  id: 'package-json',
  label: 'package.json et configuration npm',
  category: P,
  controls: [
    'Scripts exécutés automatiquement (preinstall / install / postinstall / prepare / pre* / post*)',
    'Motifs dangereux dans tous les scripts npm (curl | sh, node -e, base64…)',
    'Dépendances depuis git, URL, fichiers locaux ; versions non bornées (*, latest)',
    'Typosquatting (nom proche d\'un paquet populaire) sur les dépendances directes',
    'overrides / resolutions, publishConfig',
    'Lockfile présent et type de gestionnaire',
    '.npmrc : registre autorisé, script-shell, node-options, strict-ssl, tokens ; .yarnrc(.yml) ; .pnpmfile.cjs',
  ],
  async run(ctx) {
    const findings = [];
    const scripts = [];
    let count = 0;
    const pkgFiles = ctx.files.filter(f => f.base === 'package.json');
    for (const file of pkgFiles) {
      const text = ctx.readText(file);
      if (!text) continue;
      count++;
      let pkg;
      try { pkg = JSON.parse(text.replace(/^﻿/, '')); } catch { continue; }
      const lineOf = lineFinder(text);
      const at = (rule, needle, data) => findings.push(makeFinding(rule, Object.assign({ file: file.rel, line: lineOf(needle) }, data)));

      for (const [name, cmd] of Object.entries(pkg.scripts || {})) {
        if (typeof cmd !== 'string') continue;
        scripts.push({ fichier: file.rel, nom: name, commande: cmd });
        const ev = `"${name}": "${cmd}"`;
        if (INSTALL_HOOKS.includes(name)) at(R.LIFECYCLE, `"${name}"`, { evidence: ev });
        else if (name === 'prepare' || name === 'prepublish' || name === 'preprepare' || name === 'postprepare') at(R.PREPARE, `"${name}"`, { evidence: ev, severity: /husky|ngcc|patch-package|is-ci/.test(cmd) ? 'info' : 'low' });
        else if (/^(pre|post)(start|test|build|pack|publish|version|restart|stop|serve)$/.test(name)) at(R.OTHER_HOOK, `"${name}"`, { evidence: ev });
        if (/\bnode\s+(-e|--eval|-p)\b|\bnode\s+[^\s&|;]*\/\.[\w-]+|\bnode\s+[^\s&|;]*(tmp|temp|cache)\//i.test(cmd)) at(R.INLINE_NODE, `"${name}"`, { evidence: ev });
        const sf = scanLines([{ n: lineOf(`"${name}"`) || 1, text: cmd }], SHELL_RULES, { file: file.rel, category: P, projectType: ctx.projectType });
        sf.forEach(f => { f.evidence = ev.slice(0, 300); });
        findings.push(...sf);
      }

      const sections = ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'];
      for (const s of sections) {
        for (const [name, spec] of Object.entries(pkg[s] || {})) {
          if (typeof spec !== 'string') continue;
          const ev = `${s} > "${name}": "${spec}"`;
          if (NON_REGISTRY.test(spec) && !spec.startsWith('npm:') && !spec.startsWith('workspace:')) at(R.DEP_SOURCE, `"${name}"`, { evidence: ev, severity: /^(file:|link:)/.test(spec) ? 'medium' : /^http:\/\//i.test(spec) ? 'critical' : 'high', description: /^https?:\/\//i.test(spec) ? R.DEP_SOURCE.desc + ' Dépendance distante par URL (« Remote Dynamic Dependency », campagne PhantomRaven) : invisible pour les scanners et le registre' + (/^http:/i.test(spec) ? ', et téléchargée sans chiffrement (modifiable en transit).' : '.') : undefined });
          if (/^(\*|latest|x|)$|^>=?\s*\d[^<]*$/.test(spec.trim()) && s !== 'peerDependencies') at(R.DEP_WILDCARD, `"${name}"`, { evidence: ev });
          const t = typosquatTarget(name);
          if (t) at(R.TYPO, `"${name}"`, { evidence: ev, description: `${R.TYPO.desc} « ${name} » ressemble à « ${t} ».` });
        }
      }

      const ov = Object.assign({}, pkg.overrides, pkg.resolutions, pkg.pnpm && pkg.pnpm.overrides);
      const flat = JSON.stringify(ov);
      if (Object.keys(ov).length) {
        if (/"(git(\+\w+)?:|github:|https?:|file:)/.test(flat)) at(R.OVERRIDE_URL, '"overrides"', { evidence: flat.slice(0, 300) });
        else at(R.OVERRIDES, pkg.overrides ? '"overrides"' : '"resolutions"', { evidence: flat.slice(0, 300) });
      }
      if (pkg.publishConfig && pkg.publishConfig.registry && !allowedRegistry(pkg.publishConfig.registry, ctx)) at(R.PUBLISH, '"publishConfig"', { evidence: pkg.publishConfig.registry });

      const dir = file.rel.includes('/') ? file.rel.slice(0, file.rel.lastIndexOf('/') + 1) : '';
      const hasDeps = Object.keys(Object.assign({}, pkg.dependencies, pkg.devDependencies)).length > 0;
      const has = n => ctx.files.some(f => f.rel === dir + n);
      if (hasDeps && !dir.includes('node_modules')) {
        if (has('yarn.lock') || has('pnpm-lock.yaml')) findings.push(makeFinding(R.OTHER_LOCK, { file: file.rel, evidence: has('yarn.lock') ? 'yarn.lock' : 'pnpm-lock.yaml' }));
        else if (!has('package-lock.json') && !has('npm-shrinkwrap.json') && (dir === '' || !ctx.files.some(f => f.rel === 'package-lock.json'))) findings.push(makeFinding(R.NO_LOCK, { file: file.rel, evidence: `${file.rel} sans package-lock.json` }));
      }
    }

    // .npmrc
    for (const file of ctx.files.filter(f => f.base === '.npmrc')) {
      const text = ctx.readText(file) || '';
      count++;
      text.split(/\r?\n/).forEach((l, i) => {
        const t = l.trim();
        if (!t || t.startsWith('#') || t.startsWith(';')) return;
        let m;
        if ((m = /^(@[\w.-]+:)?registry\s*=\s*(\S+)/.exec(t)) && !allowedRegistry(m[2], ctx)) findings.push(makeFinding(R.NPMRC_REG, { file: file.rel, line: i + 1, evidence: t }));
        if (/^(script-shell|node-options|onload-script|git|shell|init-module|globalconfig|userconfig|prefix)\s*=/.test(t) || /^strict-ssl\s*=\s*false/.test(t) || /^ca\s*=\s*$/.test(t)) findings.push(makeFinding(R.NPMRC_DANGER, { file: file.rel, line: i + 1, evidence: t }));
        if (/^ignore-scripts\s*=\s*true/.test(t)) findings.push(makeFinding(R.NPMRC_IGNORE, { file: file.rel, line: i + 1, evidence: t }));
      });
    }
    for (const file of ctx.files.filter(f => f.base === '.yarnrc.yml' || f.base === '.yarnrc')) {
      const text = ctx.readText(file) || '';
      count++;
      text.split(/\r?\n/).forEach((l, i) => {
        let m;
        if (/^\s*(yarnPath|yarn-path)\s*[:\s]/.test(l) || /^\s*-?\s*path:\s*\S+\.c?js/.test(l)) findings.push(makeFinding(R.YARN_PATH, { file: file.rel, line: i + 1, evidence: l.trim() }));
        if ((m = /^\s*(npmRegistryServer|registry)\s*[:\s]\s*["']?(\S+?)["']?\s*$/.exec(l)) && !allowedRegistry(m[2], ctx)) findings.push(makeFinding(R.NPMRC_REG, { file: file.rel, line: i + 1, evidence: l.trim() }));
        if (/enableStrictSsl\s*:\s*false|strict-ssl\s+false/.test(l)) findings.push(makeFinding(R.NPMRC_DANGER, { file: file.rel, line: i + 1, evidence: l.trim() }));
      });
    }
    for (const file of ctx.files.filter(f => /^\.?pnpmfile\.c?js$/.test(f.base))) findings.push(makeFinding(R.PNPMFILE, { file: file.rel, evidence: file.rel }));

    return { findings, filesAnalyzed: count, inventory: { scriptsNpm: scripts }, notes: pkgFiles.length ? [] : ['Aucun package.json trouvé.'] };
  },
};
