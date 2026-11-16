'use strict';
/**
 * Diagnostic du poste : vérifie en quelques secondes que tout est prêt pour lancer des audits.
 *   node audit.js --diagnostic [url-gitlab-d-un-projet] [--offline]
 * Aucun secret n'est affiché (seuls la présence d'un token et le nom du compte associé le sont).
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { loadConfig, ROOT } = require('./config');
const { detectTools } = require('./env');
const { request, getJson } = require('./net');
const { tryGit } = require('./git');
const { parseGitlabUrl } = require('./clone');
const { parseProjectCodes, reportBaseName, nameFromUrl } = require('./cli');
const { sanitizeUrl } = require('./sanitize');

const OK = '✅'; const WARN = '⚠️ '; const KO = '❌'; const INFO = 'ℹ️ ';

async function runDiagnostic({ url, offline, config: cfgPath } = {}) {
  const lines = [];
  let errors = 0; let warnings = 0;
  const out = (icon, label, detail) => {
    if (icon === KO) errors++;
    if (icon === WARN) warnings++;
    lines.push(`${icon} ${label}${detail ? ' — ' + detail : ''}`);
  };
  const section = t => lines.push('', `## ${t}`);

  lines.push('# Diagnostic du poste — skill-analyse');

  // --- Logiciels ---
  section('Logiciels');
  const major = Number(process.versions.node.split('.')[0]);
  out(major >= 18 ? OK : KO, `Node.js ${process.versions.node}`, major >= 18 ? null : 'version 18 ou supérieure requise');
  let gitVersion = null;
  try { gitVersion = execFileSync('git', ['--version'], { encoding: 'utf8', windowsHide: true }).trim(); } catch { /* absent */ }
  out(gitVersion ? OK : KO, gitVersion || 'git introuvable', gitVersion ? null : 'installer git (version portable possible) et l\'ajouter au PATH');
  const tools = detectTools();
  const present = Object.entries(tools).filter(([, v]) => v).map(([k]) => k);
  const absent = Object.entries(tools).filter(([, v]) => !v).map(([k]) => k);
  out(INFO, `Outils optionnels présents : ${present.join(', ') || 'aucun'}`, absent.length ? `absents (non bloquant) : ${absent.join(', ')} — voir tools\\setup-tools.ps1` : null);

  // --- Configuration ---
  section('Configuration');
  let cfg = null;
  try { cfg = loadConfig(cfgPath); out(OK, 'Configuration lisible'); } catch (e) { out(KO, 'Configuration illisible', e.message); }
  const local = path.join(ROOT, 'config', 'settings.local.json');
  out(fs.existsSync(local) ? OK : WARN, 'config\\settings.local.json', fs.existsSync(local) ? 'présent' : 'absent : lancer integration\\install.ps1 ou copier settings.json');
  if (cfg) {
    out(cfg.npm.artifactoryUrl ? OK : WARN, 'URL Artifactory (npm.artifactoryUrl)', cfg.npm.artifactoryUrl ? sanitizeUrl(cfg.npm.artifactoryUrl) : 'non renseignée : les requêtes iront vers registry.npmjs.org et les sources Artifactory du lockfile seront signalées');
    out(cfg.gitlab.url ? OK : INFO, 'Instance GitLab (gitlab.url)', cfg.gitlab.url || 'non renseignée : déduite de l\'URL de chaque projet');
    out((cfg.npm.scopesInternes || []).length ? OK : WARN, 'Scopes npm internes (npm.scopesInternes)', (cfg.npm.scopesInternes || []).join(', ') || 'vides : la confusion de dépendances et la protection des noms internes sont inactives');
    out((cfg.domaines.internes || []).length ? OK : WARN, 'Domaines internes (domaines.internes)', (cfg.domaines.internes || []).join(', ') || 'vides : vos domaines d\'entreprise seront signalés comme externes');
    out((cfg.domaines.emailsDeveloppeurs || []).length ? OK : INFO, 'Domaines email des développeurs', (cfg.domaines.emailsDeveloppeurs || []).join(', ') || 'vides : contrôle des auteurs externes désactivé');
    out((cfg.docker.registresAutorises || []).length ? OK : INFO, 'Registres Docker autorisés', (cfg.docker.registresAutorises || []).join(', ') || 'vides : contrôle du registre des images désactivé');
  }
  for (const d of ['reports', 'workspace']) {
    const p = path.join(ROOT, d);
    try { fs.mkdirSync(p, { recursive: true }); const t = path.join(p, '.ecriture-test'); fs.writeFileSync(t, 'ok'); fs.unlinkSync(t); out(OK, `Dossier ${d}\\ accessible en écriture`); }
    catch (e) { out(KO, `Dossier ${d}\\ non accessible en écriture`, e.message); }
  }

  // --- Réseau ---
  section('Réseau');
  const proxy = process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy;
  out(INFO, 'Proxy', proxy ? sanitizeUrl(proxy) + (process.env.NO_PROXY ? ` (NO_PROXY : ${process.env.NO_PROXY})` : '') : 'aucun (variable HTTPS_PROXY non définie)');
  const ca = process.env.NODE_EXTRA_CA_CERTS;
  if (ca) out(fs.existsSync(ca) ? OK : KO, 'Certificat d\'entreprise (NODE_EXTRA_CA_CERTS)', fs.existsSync(ca) ? ca : `fichier introuvable : ${ca}`);
  else out(INFO, 'Certificat d\'entreprise (NODE_EXTRA_CA_CERTS)', 'non défini — à définir si les accès HTTPS échouent avec une erreur de certificat');

  const gl = url ? parseGitlabUrl(url) : null;
  const gitlabBase = cfg && (cfg.gitlab.url || (gl ? `https://${gl.host}` : ''));
  if (offline) {
    out(INFO, 'Tests réseau ignorés (--offline)');
  } else if (cfg) {
    const probe = async (label, u, headers) => {
      try {
        const r = await request(u, { timeout: 8000, maxBytes: 512 * 1024, headers });
        return { ok: true, status: r.status };
      } catch (e) {
        const msg = /certificate|self[- ]signed|unable to verify/i.test(e.message) ? `erreur de certificat (${e.message}) → définir NODE_EXTRA_CA_CERTS` : e.message;
        return { ok: false, msg, label };
      }
    };
    const reg = cfg.npm.registreRequetes;
    const npmTok = process.env[cfg.npm.tokenEnv || 'NPM_TOKEN'];
    const rReg = await probe('registre', reg + '-/ping', npmTok && cfg.npm.artifactoryUrl ? { Authorization: 'Bearer ' + npmTok } : {});
    out(rReg.ok ? (rReg.status === 401 || rReg.status === 403 ? WARN : OK) : WARN, `Registre npm (${sanitizeUrl(reg)})`, rReg.ok ? (rReg.status === 401 || rReg.status === 403 ? `accessible mais authentification requise (HTTP ${rReg.status}) : définir ${cfg.npm.tokenEnv || 'NPM_TOKEN'}` : `HTTP ${rReg.status}`) : `inaccessible : ${rReg.msg} — dates de publication et inspection des archives désactivées`);
    const rOsv = await probe('osv', 'https://api.osv.dev/v1/vulns/GHSA-0000-0000-0000');
    out(rOsv.ok ? OK : WARN, 'Base de vulnérabilités OSV (api.osv.dev)', rOsv.ok ? 'accessible' : `inaccessible : ${rOsv.msg} — CVE et paquets malveillants connus non vérifiés (la liste locale rules/ioc.json reste utilisée)`);
    if (gitlabBase && cfg.gitlab.api !== false) {
      const rGl = await probe('gitlab', gitlabBase.replace(/\/$/, '') + '/api/v4/version');
      // 200 (version publique) ou 401 (authentification requise) = instance GitLab ; autre code = pas une API GitLab
      const isGitlab = rGl.ok && (rGl.status === 200 || rGl.status === 401);
      out(isGitlab ? OK : rGl.ok ? WARN : KO, `API GitLab (${gitlabBase})`, isGitlab ? `joignable (HTTP ${rGl.status})` : rGl.ok ? `HTTP ${rGl.status} : ne semble pas être une instance GitLab (vérifier gitlab.url)` : `inaccessible : ${rGl.msg}`);
    } else {
      out(INFO, 'API GitLab', cfg.gitlab.api === false ? 'désactivée (gitlab.api = false) : aucun appel' : 'non testée : renseigner gitlab.url ou passer l\'URL d\'un projet (node audit.js --diagnostic <url>)');
    }

    // --- Token GitLab ---
    section('Token GitLab');
    const tokenEnv = cfg.gitlab.tokenEnv || 'GITLAB_TOKEN';
    const token = process.env[tokenEnv];
    if (cfg.gitlab.api === false) {
      out(INFO, 'API GitLab désactivée (gitlab.api = false)', 'analyse par clone local uniquement — aucun token nécessaire');
    } else if (!token) {
      out(WARN, `Variable ${tokenEnv} absente`, 'les contrôles merge requests / approbations / protections ne seront pas faits. PowerShell : $env:GITLAB_TOKEN = "<token read_api>"');
    } else if (gitlabBase && /^https:/i.test(gitlabBase)) {
      const base = gitlabBase.replace(/\/$/, '') + '/api/v4';
      const headers = { 'PRIVATE-TOKEN': token };
      const me = await getJson(base + '/user', { headers, timeout: 8000 }).catch(e => ({ status: 0, err: e.message }));
      if (me.status === 200 && me.json) {
        out(OK, `Token valide (compte : ${me.json.username})`);
        const self = await getJson(base + '/personal_access_tokens/self', { headers, timeout: 8000 }).catch(() => null);
        if (self && self.status === 200 && self.json) {
          const scopes = self.json.scopes || [];
          out(scopes.some(s => /^(read_api|api)$/.test(s)) ? OK : KO, `Droits du token : ${scopes.join(', ') || '?'}`, scopes.some(s => /^(read_api|api)$/.test(s)) ? null : 'le droit read_api est nécessaire');
          if (self.json.expires_at) out(INFO, `Expiration du token : ${self.json.expires_at}`);
        }
      } else out(KO, 'Token refusé par GitLab', me.status ? `HTTP ${me.status}` : me.err);
    } else {
      out(INFO, `Variable ${tokenEnv} présente`, 'validité non testée (instance GitLab inconnue ou non HTTPS)');
    }
  }

  // --- Projet de test ---
  if (url) {
    section('Projet de test');
    const codes = parseProjectCodes(url);
    const id = reportBaseName({ produit: codes.produit, solution: codes.solution, projet: nameFromUrl(url) });
    out(codes.produit && codes.solution ? OK : WARN, `Identifiant du rapport : ${id}`, codes.produit && codes.solution ? `produit ${codes.produit}, solution ${codes.solution}` : 'code produit (pXXXX) ou solution (sXXXX) non trouvé dans l\'URL');
    if (!offline && gitVersion) {
      const ls = tryGit(['ls-remote', '--heads', '--', url], process.cwd(), { timeout: 60000 });
      out(ls !== null ? OK : KO, 'Accès git au dépôt (clone possible)', ls !== null ? `${ls.split('\n').filter(Boolean).length} branche(s) visibles` : 'refusé ou inaccessible : vérifier la clé SSH / les identifiants git');
      const token = cfg && cfg.gitlab.api !== false && process.env[cfg.gitlab.tokenEnv || 'GITLAB_TOKEN'];
      if (token && gl && gitlabBase && /^https:/i.test(gitlabBase)) {
        const r = await getJson(`${gitlabBase.replace(/\/$/, '')}/api/v4/projects/${encodeURIComponent(gl.projectPath)}`, { headers: { 'PRIVATE-TOKEN': token }, timeout: 8000 }).catch(() => null);
        if (r && r.status === 200 && r.json) {
          const perm = r.json.permissions || {};
          const level = Math.max((perm.project_access && perm.project_access.access_level) || 0, (perm.group_access && perm.group_access.access_level) || 0);
          const role = { 10: 'Guest', 20: 'Reporter', 30: 'Developer', 40: 'Maintainer', 50: 'Owner' }[level] || 'inconnu';
          out(OK, `Projet accessible via l'API (rôle : ${role})`);
          out(level >= 40 ? OK : WARN, 'Contrôles de plateforme (webhooks, miroirs, clés, variables CI)', level >= 40 ? 'possibles' : 'nécessitent le rôle Maintainer : ils seront marqués « non évalué »');
        } else out(KO, 'Projet inaccessible via l\'API', r ? `HTTP ${r.status}` : 'erreur réseau');
      }
    }
  }

  lines.push('', '---', errors ? `${KO} ${errors} problème(s) bloquant(s), ${warnings} avertissement(s).` : warnings ? `${OK} Prêt pour les audits, avec ${warnings} avertissement(s) (fonctionnalités réduites).` : `${OK} Tout est prêt.`);
  return { text: lines.join('\n'), errors, warnings };
}

module.exports = { runDiagnostic };
