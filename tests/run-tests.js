'use strict';
/**
 * Tests de détection : chaque faux projet piégé doit déclencher les règles attendues,
 * et le projet propre doit obtenir une bonne note.
 */
const path = require('path');
const fs = require('fs');
const { buildAll } = require('./fixtures');
const { runAudit } = require('../lib/runner');

const TMP = path.join(__dirname, '.tmp');
const OUT = path.join(TMP, 'reports');

const EXPECT = {
  fePiege: {
    name: 'fe01', type: 'fe', maxGrade: 'E',
    rules: ['PKG_SCRIPT_INSTALLATION', 'SH_PIPE_TO_SHELL', 'PKG_TYPOSQUATTING', 'PKG_DEPENDANCE_HORS_REGISTRE', 'PKG_VERSION_NON_BORNEE', 'NPMRC_REGISTRE_NON_AUTORISE', 'NPMRC_OPTION_DANGEREUSE',
      'DEP_SOURCE_NON_AUTORISEE', 'DEP_INTEGRITE_ABSENTE', 'DEP_SCRIPT_INSTALLATION', 'DEP_SCRIPT_INSTALLATION_CONNU',
      'DOCKER_IMAGE_NON_FIGEE', 'DOCKER_SECRET_ENV', 'DOCKER_NPM_SANS_IGNORE_SCRIPTS', 'DOCKER_ADD_URL', 'DOCKER_PORT_INATTENDU', 'DOCKER_SCRIPT_ABSENT_DU_DEPOT', 'DOCKER_UTILISATEUR_ROOT', 'NET_PUBLIC_IP_URL',
      'SRV_PORT_INATTENDU', 'SRV_PROXY_IP_PUBLIQUE', 'SRV_SCRIPT_EMBARQUE', 'SRV_PROXY_OUVERT', 'SRV_MIRROR', 'SRV_PROXY_EXTERNE', 'SRV_ALIAS_TRAVERSAL', 'SRV_ENTETES_SECURITE',
      'CODE_OBFUSCATEUR', 'CODE_ECHAPPEMENTS_HEX', 'CODE_UNICODE_BIDI', 'CODE_KEYLOGGER', 'CODE_EXFILTRATION', 'CODE_EVAL', 'NET_SUSPICIOUS_DOMAIN', 'CODE_SCRIPT_EXTERNE_HTML', 'CODE_DETOURNEMENT_GLOBAL',
      'ANGULAR_SCRIPT_GLOBAL', 'ANGULAR_SCRIPT_DISTANT',
      'SECRET_GITLAB', 'SECRET_AWS', 'SH_REVERSE_SHELL',
      'STRUCT_SCRIPT_DANS_SOURCES', 'STRUCT_CODE_DANS_ASSETS', 'STRUCT_FAUSSE_IMAGE', 'STRUCT_MANIFESTE_K8S_HORS_PLACE', 'K8S_PRIVILEGIE',
      // nouvelles vérifications (attaques 2025-2026)
      'IDE_TACHE_AUTOMATIQUE_DANGEREUSE', 'IDE_TACHES_AUTO_AUTORISEES', 'IDE_CONFIANCE_DESACTIVEE', 'IDE_CHEMIN_EXECUTABLE', 'IDE_DEVCONTAINER_COMMANDE_HOTE',
      'IA_SERVEUR_MCP_DANGEREUX', 'IA_FICHIER_INSTRUCTIONS', 'IA_INJECTION_CONSIGNES', 'UNICODE_CARACTERES_TAGS', 'UNICODE_SELECTEURS_VARIANTE',
      'NET_DETOURNEMENT_AGENT_IA', 'CODE_PROPAGATION_NPM', 'CODE_API_GITHUB_ECRITURE', 'CODE_SCANNER_SECRETS_EMBARQUE', 'NET_C2_BLOCKCHAIN',
      'DEP_LOCKFILE_INCOHERENT', 'DEP_VERSION_COMPROMISE_CONNUE', 'STRUCT_FICHIER_IOC', 'DOCKER_DOCKERIGNORE_ABSENT', 'ANGULAR_SOURCEMAP_PRODUCTION', 'ANGULAR_CSP_ABSENTE'],
  },
  bffPiege: {
    name: 'bff01', type: 'bff', maxGrade: 'E',
    rules: ['CODE_CHILD_PROCESS', 'CODE_EXEC_ENTREE_UTILISATEUR', 'CODE_ROUTE_SUSPECTE', 'CODE_TLS_DESACTIVE', 'CODE_DUMP_ENV', 'CODE_SERVEUR_RESEAU', 'CODE_PORT_ECOUTE_INATTENDU', 'NET_PUBLIC_IP_URL',
      'SHELL_HOOK_RESEAU', 'SH_PIPE_TO_SHELL', 'PKG_SCRIPT_PREPARE', 'PKG_TYPOSQUATTING', 'DEP_TYPOSQUATTING', 'DEP_SCRIPT_INSTALLATION', 'DOCKER_UTILISATEUR_ROOT', 'DOCKER_NPM_SANS_IGNORE_SCRIPTS'],
  },
  helmPiege: {
    name: 'helm01', type: 'helm', maxGrade: 'E',
    rules: ['HELM_DEPOT_NON_AUTORISE', 'SECRET_GENERIQUE', 'K8S_HOOK_HELM', 'SH_PIPE_TO_SHELL', 'K8S_SHELL_C', 'K8S_ESPACE_NOMS_HOTE', 'K8S_INIT_CONTAINER', 'K8S_PRIVILEGIE', 'K8S_CAPACITES',
      'K8S_HOSTPATH', 'K8S_HOSTPATH_SENSIBLE', 'SRV_PROXY_EXTERNE', 'SRV_SCRIPT_EMBARQUE', 'K8S_RBAC_JOKER', 'K8S_RESSOURCE_SENSIBLE', 'K8S_EXPOSITION_SERVICE', 'K8S_INGRESS_SNIPPET', 'NET_PUBLIC_IP_URL'],
  },
  feClean: { name: 'fe-propre', type: 'fe', minGrade: 'B', rules: [] },
  git: {
    name: 'bff02', type: 'bff', maxGrade: 'E',
    rules: ['GIT_TAG_NON_FUSIONNE_SENSIBLE', 'GIT_TAG_FORMAT', 'GIT_COMMIT_DIRECT_PROBABLE', 'GIT_DATE_FUTURE', 'GIT_MESSAGE_TROMPEUR', 'GIT_CODE_HORS_BRANCHE_PRINCIPALE'],
    config: { domaines: { emailsDeveloppeurs: ['entreprise.fr'] } },
    extraRules: ['GIT_EMAIL_EXTERNE'],
  },
};

const GR = ['A', 'B', 'C', 'D', 'E'];

(async () => {
  const dirs = buildAll(TMP);
  let failures = 0;
  for (const [key, exp] of Object.entries(EXPECT)) {
    let cfgPath;
    if (exp.config) { cfgPath = path.join(TMP, key + '-config.json'); fs.writeFileSync(cfgPath, JSON.stringify(exp.config)); }
    const { res, paths } = await runAudit({ name: exp.name, path: dirs[key], offline: true, noApi: true, out: OUT, noSave: true, quiet: true, config: cfgPath, days: 365 });
    const found = new Set(res.constats.map(f => f.rule));
    const missing = exp.rules.concat(exp.extraRules || []).filter(r => !found.has(r));
    const errors = res.scanners.filter(s => s.status === 'erreur');
    const n = res.notation;
    let ok = !missing.length && !errors.length && res.projet.type === exp.type;
    if (exp.minGrade && GR.indexOf(n.note) > GR.indexOf(exp.minGrade)) ok = false;
    console.log(`${ok ? '✅' : '❌'} ${key.padEnd(10)} type=${res.projet.type} note=${n.note} score=${n.score} constats=${res.constats.length} (crit ${n.compte.critical}, élevés ${n.compte.high})`);
    if (missing.length) console.log('   règles non déclenchées : ' + missing.join(', '));
    if (errors.length) errors.forEach(s => console.log(`   erreur scanner ${s.id} : ${s.notes.join(' ; ')}`));
    if (exp.minGrade && GR.indexOf(n.note) > GR.indexOf(exp.minGrade)) {
      console.log(`   note attendue ≥ ${exp.minGrade} ; constats :`);
      res.constats.filter(f => f.severity !== 'info').forEach(f => console.log(`     - ${f.severity} ${f.rule} ${f.file || ''}:${f.line || ''} ${f.evidence || ''}`));
    }
    if (!ok) failures++;
    if (process.env.VERBOSE) console.log('   rapport : ' + paths.rapport);
  }

  // Profil helm : merges / commits directs ramenés à Info, contrôles forts conservés
  {
    const { res } = await runAudit({ name: 'helm-git', path: dirs.git, type: 'helm', offline: true, noApi: true, out: OUT, noSave: true, quiet: true, days: 365 });
    const by = r => res.constats.filter(f => f.rule === r);
    const direct = by('GIT_COMMIT_DIRECT_PROBABLE');
    const ok = direct.length === 1 && direct[0].severity === 'info' && by('GIT_MESSAGE_TROMPEUR').every(f => f.severity === 'info')
      && by('GIT_DATE_FUTURE').some(f => f.severity === 'high') && by('GIT_TAG_NON_FUSIONNE_SENSIBLE').some(f => f.severity === 'critical');
    console.log(`${ok ? '✅' : '❌'} profil helm : commits directs en Info (regroupés), date future et tag non fusionné toujours signalés`);
    if (!ok) failures++;
  }

  // Mode lot : fichier de projets avec options propres, synthèse consolidée
  {
    const { execFileSync } = require('child_process');
    const list = path.join(TMP, 'projets.txt');
    fs.writeFileSync(list, `# lot de test\nfe01 --path "${dirs.fePiege}"\nfe-propre;--path "${dirs.feClean}"\nhelm01 --path "${dirs.helmPiege}" --type helm\n`);
    let out = '';
    try { out = execFileSync(process.execPath, [path.join(__dirname, '..', 'audit-lot.js'), '--fichier', list, '--offline', '--no-save', '--out', OUT], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch (e) { out = String(e.stdout || ''); }
    const m = /SYNTHESE (.+)/.exec(out);
    const synth = m ? fs.readFileSync(m[1].trim(), 'utf8') : '';
    const rows = synth.split('\n').filter(l => /^\| (fe01|fe-propre|helm01) /.test(l));
    const ok = rows.length === 3 && rows[rows.length - 1].startsWith('| fe-propre ');
    console.log(`${ok ? '✅' : '❌'} mode lot : 3 projets analysés, synthèse triée du plus au moins risqué`);
    if (!ok) { failures++; console.log(out); }
  }

  console.log(failures ? `\n${failures} test(s) en échec` : '\nTous les tests passent.');
  // Les projets piégés générés ressemblent volontairement à des malwares : on les supprime pour
  // ne pas déclencher d'antivirus (archive, email…). KEEP=1 pour les conserver et les examiner.
  if (!process.env.KEEP) {
    fs.rmSync(TMP, { recursive: true, force: true, maxRetries: 5 });
    console.log('Fichiers de test supprimés (KEEP=1 pour les conserver).');
  }
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
