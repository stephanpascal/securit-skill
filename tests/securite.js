'use strict';
/**
 * Tests de non-fuite :
 * 1. aucune requête réseau n'est émise en mode --offline (http/https/net interceptés) ;
 * 2. aucun secret en clair dans les rapports produits ;
 * 3. tokens jamais envoyés à un hôte non prévu ; URL "resolved" du lockfile jamais contactée hors registres autorisés ;
 * 4. paquets internes jamais envoyés aux services publics.
 */
const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const net = require('net');

const TMP = path.join(__dirname, '.tmp-securite');
let failures = 0;
const check = (ok, label) => { console.log(`${ok ? '✅' : '❌'} ${label}`); if (!ok) failures++; };

// --- Interception réseau (avant de charger l'outil) ---
let netCalls = [];
const wrap = (mod, name) => { const orig = mod[name]; mod[name] = function (...a) { netCalls.push(`${name} ${typeof a[0] === 'string' ? a[0] : (a[0] && (a[0].hostname || a[0].host)) || ''}`); return orig.apply(this, a); }; };
wrap(http, 'request'); wrap(http, 'get'); wrap(https, 'request'); wrap(https, 'get'); wrap(net, 'connect'); wrap(net, 'createConnection');

const { buildAll } = require('./fixtures');
const { runAudit } = require('../lib/runner');
const { maskString, sanitizeUrl, sanitizeText } = require('../lib/sanitize');
const deps = require('../scanners/dependencies');
const gitlabApi = require('../scanners/gitlab-api');
const { loadConfig } = require('../lib/config');

const J = (...p) => p.join('');
const SECRETS = [J('gl', 'pat-', 'Zx9', 'AbCdEfGhIjKlMnOpQrSt'), J('AK', 'IA', 'QWERTYUIOPASDFGH'), 'abcd1234secretvalue', 'SuperSecretValue123'];

(async () => {
  // 1 + 2 : audits complets hors ligne
  const dirs = buildAll(TMP);
  netCalls = [];
  const outputs = [];
  for (const [key, name] of [['fePiege', 'fe01'], ['bffPiege', 'bff01'], ['helmPiege', 'helm01'], ['git', 'bff02']]) {
    const { paths } = await runAudit({ name, path: dirs[key], offline: true, out: path.join(TMP, 'reports'), noSave: true, quiet: true, days: 365 });
    outputs.push(...Object.values(paths));
  }
  check(netCalls.length === 0, `Mode hors ligne : aucune connexion réseau émise (${netCalls.length} tentative(s)${netCalls.length ? ' : ' + netCalls.slice(0, 3).join(', ') : ''})`);
  const leaked = [];
  for (const p of outputs) { const t = fs.readFileSync(p, 'utf8'); for (const s of SECRETS) if (t.includes(s)) leaked.push(`${path.basename(p)} contient ${s.slice(0, 6)}…`); }
  check(leaked.length === 0, `Rapports (md + json) : aucun secret en clair${leaked.length ? ' — ' + leaked.join(' ; ') : ''}`);

  // Masquage unitaire
  const sample = `token=${SECRETS[0]} key ${SECRETS[1]} //reg/:_authToken=npm_${'a'.repeat(36)} https://bob:hunter2pass@git.exemple.fr/x.git password: "MonMotDePasse!"`;
  const masked = maskString(sample);
  check(!SECRETS.slice(0, 2).some(s => masked.includes(s)) && !masked.includes('hunter2pass') && !masked.includes('MonMotDePasse') && !masked.includes('a'.repeat(36)), 'Masquage : tokens, clé AWS, token npm, identifiants d\'URL et mots de passe');
  check(sanitizeUrl('https://user:glpat-xyz@gitlab.ex.fr/g/p.git') === 'https://gitlab.ex.fr/g/p.git', 'URL du projet : identifiants retirés');
  check(!sanitizeText('fatal: https://u:s3cr3t@h/x').includes('s3cr3t'), 'Messages d\'erreur git : identifiants retirés');

  // 3 : tokens et URL du lockfile
  const cfg = loadConfig();
  cfg.npm.artifactoryUrl = 'https://artifactory.entreprise.fr/artifactory/api/npm/npm-virtual/';
  cfg.npm.registresAutorises = ['https://artifactory.entreprise.fr/artifactory/api/npm/npm-virtual/'];
  cfg.npm.registreRequetes = cfg.npm.artifactoryUrl;
  cfg.npm.scopesInternes = ['@entreprise'];
  const ctx = { config: cfg };
  process.env.NPM_TOKEN = 'jeton-de-test';
  const evil = deps.tarballUrl({ name: 'x', version: '1.0.0', resolved: 'https://evil.example.org/x-1.0.0.tgz' }, ctx);
  check(evil.startsWith(cfg.npm.artifactoryUrl), 'URL "resolved" hors registre autorisé : jamais contactée (remplacée par Artifactory)');
  const internal = deps.tarballUrl({ name: 'x', version: '1.0.0', resolved: 'http://10.0.0.5/admin' }, ctx);
  check(internal.startsWith(cfg.npm.artifactoryUrl), 'URL "resolved" interne/HTTP (SSRF) : jamais contactée');
  check(!deps.authHeaders(ctx, 'https://artifactory.entreprise.fr.evil.com/x').Authorization && !deps.authHeaders(ctx, 'https://evil.com/artifactory.entreprise.fr/').Authorization, 'Token Artifactory : jamais envoyé à un autre hôte');
  check(!!deps.authHeaders(ctx, cfg.npm.artifactoryUrl + 'x').Authorization, 'Token Artifactory : envoyé à l\'hôte Artifactory configuré');
  check(!deps.authHeaders(ctx, 'http://artifactory.entreprise.fr/x').Authorization, 'Token Artifactory : jamais envoyé en HTTP');
  check(deps.isInternal('@entreprise/lib', ctx) && !deps.isInternal('lodash', ctx), 'Paquets internes identifiés (exclus d\'OSV et du registre public)');

  // Token GitLab vers un hôte différent de l'instance configurée
  process.env.GITLAB_TOKEN = 'jeton-gitlab-test';
  netCalls = [];
  const cfg2 = loadConfig(); cfg2.gitlab.url = 'https://gitlab.entreprise.fr';
  const r = await gitlabApi.run({ config: cfg2, options: {}, offline: false, network: { gitlab: true }, gitlab: { host: 'gitlab.attaquant.com', projectPath: 'g/p' } });
  check(r.status === 'non exécuté' && netCalls.length === 0, 'Token GitLab : jamais envoyé à un hôte différent de l\'instance configurée');
  netCalls = [];
  const cfg3 = loadConfig(); cfg3.gitlab.url = 'http://gitlab.entreprise.fr';
  const r3 = await gitlabApi.run({ config: cfg3, options: {}, offline: false, network: { gitlab: true }, gitlab: { host: 'gitlab.entreprise.fr', projectPath: 'g/p' } });
  check(r3.status === 'non exécuté' && netCalls.length === 0, 'Token GitLab : jamais envoyé en HTTP');
  delete process.env.GITLAB_TOKEN; delete process.env.NPM_TOKEN;

  if (!process.env.KEEP) fs.rmSync(TMP, { recursive: true, force: true, maxRetries: 5 });
  console.log(failures ? `\n${failures} test(s) de sécurité en échec` : '\nTous les tests de sécurité passent.');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
