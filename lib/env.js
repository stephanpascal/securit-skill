'use strict';
/**
 * Diagnostic de l'environnement : outils externes disponibles et accès réseau.
 */
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { reachable } = require('./net');
const { ROOT } = require('./config');

const TOOLS = ['gitleaks', 'trivy', 'osv-scanner', 'hadolint', 'helm', 'kube-linter'];

function findTool(name) {
  const exe = process.platform === 'win32' ? name + '.exe' : name;
  const local = path.join(ROOT, 'tools', 'bin', exe);
  if (fs.existsSync(local)) return local;
  try {
    const out = execFileSync(process.platform === 'win32' ? 'where' : 'which', [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
    const first = out.split(/\r?\n/).find(Boolean);
    return first ? first.trim() : null;
  } catch { return null; }
}

function detectTools() {
  const res = {};
  for (const t of TOOLS) res[t] = findTool(t);
  return res;
}

async function networkDiagnostic(cfg, { offline, gitlabHost } = {}) {
  if (offline) return { osv: false, registre: false, gitlab: false, horsLigne: true };
  const gitlabBase = cfg.gitlab.url || (gitlabHost ? 'https://' + gitlabHost : '');
  const [osv, registre, gitlab] = await Promise.all([
    cfg.enLigne.osv ? reachable('https://api.osv.dev/v1/vulns/GHSA-0000-0000-0000') : Promise.resolve(false),
    reachable(cfg.npm.registreRequetes + '-/ping'),
    gitlabBase ? reachable(gitlabBase.replace(/\/$/, '') + '/api/v4/version') : Promise.resolve(false),
  ]);
  return { osv, registre, gitlab, horsLigne: false };
}

module.exports = { detectTools, networkDiagnostic, findTool, TOOLS };
