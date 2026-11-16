'use strict';
/**
 * Intégration optionnelle d'outils externes s'ils sont présents (tools/bin ou PATH).
 * Aucun n'est obligatoire : leur absence est simplement mentionnée dans le rapport.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { makeFinding } = require('../lib/finding');
const { truncate, maskValue } = require('../lib/util');

const O = 'outils';

function run(bin, args, opts = {}) {
  try {
    return execFileSync(bin, args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024, timeout: opts.timeout || 10 * 60 * 1000, stdio: ['ignore', 'pipe', 'pipe'], cwd: opts.cwd, windowsHide: true, env: Object.assign({}, process.env, opts.env || {}) });
  } catch (e) {
    if (e.stdout && String(e.stdout).trim()) return String(e.stdout); // beaucoup d'outils sortent en code ≠ 0 quand ils trouvent quelque chose
    throw new Error(truncate(String(e.stderr || e.message), 300));
  }
}

function rel(root, p) { return p ? path.relative(root, path.resolve(root, p)).replace(/\\/g, '/') : null; }

const MAP_SEV = s => ({ CRITICAL: 'high', HIGH: 'medium', MEDIUM: 'low', LOW: 'info', UNKNOWN: 'low', error: 'medium', warning: 'low', info: 'info', style: 'info' })[s] || 'low';

async function gitleaks(bin, ctx, tmp) {
  const out = path.join(tmp, 'gitleaks.json');
  let args = ['dir', ctx.root, '--report-format', 'json', '--report-path', out, '--no-banner', '--exit-code', '0'];
  try { run(bin, args); } catch { args = ['detect', '--no-git', '--source', ctx.root, '--report-format', 'json', '--report-path', out, '--no-banner', '--exit-code', '0']; run(bin, args); }
  const list = JSON.parse(fs.readFileSync(out, 'utf8') || '[]');
  return list.slice(0, 200).map(l => makeFinding({ id: 'GITLEAKS_' + String(l.RuleID || 'secret').toUpperCase().replace(/[^A-Z0-9]+/g, '_'), sev: 'high', cat: 'secrets', title: `Secret détecté par gitleaks (${l.RuleID})`, desc: l.Description || 'Secret détecté.', fix: 'Révoquer le secret et le retirer du dépôt.' }, { file: rel(ctx.root, l.File), line: l.StartLine, evidence: maskValue(l.Secret || l.Match || ''), source: 'gitleaks' }));
}

async function trivy(bin, ctx) {
  const args = ['fs', '--scanners', 'vuln,misconfig,secret', '--format', 'json', '--quiet', '--timeout', '15m', '--skip-version-check'];
  if (ctx.offline || !ctx.network.osv) args.push('--skip-db-update', '--skip-java-db-update', '--offline-scan');
  args.push(ctx.root);
  const json = JSON.parse(run(bin, args, { timeout: 20 * 60 * 1000 }));
  const out = [];
  for (const res of json.Results || []) {
    for (const m of res.Misconfigurations || []) {
      if (m.Status && m.Status !== 'FAIL') continue;
      out.push(makeFinding({ id: 'TRIVY_' + (m.ID || m.AVDID || 'MISCONF'), sev: MAP_SEV(m.Severity) === 'info' ? 'low' : ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' })[m.Severity] || 'low', cat: res.Type === 'dockerfile' ? 'docker' : 'k8s', title: `[trivy] ${m.Title}`, desc: m.Description || '', fix: m.Resolution || '' }, { file: res.Target, line: m.CauseMetadata && m.CauseMetadata.StartLine, evidence: m.Message, source: 'trivy' }));
    }
    for (const s of res.Secrets || []) out.push(makeFinding({ id: 'TRIVY_SECRET_' + (s.RuleID || ''), sev: 'high', cat: 'secrets', title: `[trivy] ${s.Title}`, desc: 'Secret détecté.', fix: 'Révoquer et retirer.' }, { file: res.Target, line: s.StartLine, evidence: maskValue(s.Match || ''), source: 'trivy' }));
    const vulns = res.Vulnerabilities || [];
    const byPkg = new Map();
    for (const v of vulns) { const k = `${v.PkgName}@${v.InstalledVersion}`; if (!byPkg.has(k)) byPkg.set(k, []); byPkg.get(k).push(v); }
    for (const [k, vs] of byPkg) {
      const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
      const worst = vs.map(v => v.Severity).sort((a, b) => order.indexOf(a) - order.indexOf(b))[0];
      out.push(makeFinding({ id: 'TRIVY_VULNERABILITE', sev: MAP_SEV(worst), cat: 'dependances', title: '[trivy] Vulnérabilité connue', desc: 'Vulnérabilités détectées par trivy.', fix: 'Mettre à jour vers une version corrigée.' }, { file: res.Target, evidence: `${k} — ${vs.slice(0, 5).map(v => `${v.VulnerabilityID} (${v.Severity})`).join(', ')}${vs.length > 5 ? ` (+${vs.length - 5})` : ''}`, source: 'trivy' }));
    }
  }
  return out;
}

async function osvScanner(bin, ctx) {
  let txt;
  try { txt = run(bin, ['scan', 'source', '--format', 'json', '-r', ctx.root]); } catch { txt = run(bin, ['--format', 'json', '-r', ctx.root]); }
  const json = JSON.parse(txt);
  const out = [];
  for (const r of json.results || []) {
    for (const p of r.packages || []) {
      const ids = (p.vulnerabilities || []).map(v => v.id);
      if (!ids.length) continue;
      const mal = ids.filter(i => i.startsWith('MAL-'));
      out.push(makeFinding({ id: mal.length ? 'OSV_SCANNER_MALVEILLANT' : 'OSV_SCANNER_VULNERABILITE', sev: mal.length ? 'critical' : 'low', cat: 'dependances', title: mal.length ? '[osv-scanner] Paquet malveillant connu' : '[osv-scanner] Vulnérabilité connue', desc: 'Résultat osv-scanner.', fix: mal.length ? 'Retirer immédiatement.' : 'Mettre à jour.' }, { file: rel(ctx.root, r.source && r.source.path), evidence: `${p.package.name}@${p.package.version} — ${ids.slice(0, 6).join(', ')}`, source: 'osv-scanner' }));
    }
  }
  return out;
}

async function hadolint(bin, ctx) {
  const out = [];
  for (const f of ctx.files.filter(f => /^(dockerfile|containerfile)([._-].*)?$/i.test(f.base))) {
    const list = JSON.parse(run(bin, ['-f', 'json', '--no-fail', f.abs]) || '[]');
    for (const l of list) {
      if (l.level === 'style' || l.level === 'info') continue;
      out.push(makeFinding({ id: 'HADOLINT_' + l.code, sev: l.level === 'error' ? 'medium' : 'low', cat: 'docker', title: `[hadolint] ${l.code}`, desc: l.message, fix: `Voir https://github.com/hadolint/hadolint/wiki/${l.code}` }, { file: f.rel, line: l.line, evidence: l.message, source: 'hadolint' }));
    }
  }
  return out;
}

async function kubeLinter(bin, ctx) {
  const json = JSON.parse(run(bin, ['lint', ctx.root, '--format', 'json']) || '{}');
  return (json.Reports || []).slice(0, 200).map(r => makeFinding({ id: 'KUBELINTER_' + String(r.Check).toUpperCase().replace(/[^A-Z0-9]+/g, '_'), sev: 'low', cat: 'k8s', title: `[kube-linter] ${r.Check}`, desc: r.Diagnostic && r.Diagnostic.Message, fix: r.Remediation || '' }, { file: rel(ctx.root, r.Object && r.Object.Metadata && r.Object.Metadata.FilePath), evidence: r.Diagnostic && r.Diagnostic.Message, source: 'kube-linter' }));
}

const RUNNERS = { gitleaks, trivy, 'osv-scanner': osvScanner, hadolint, 'kube-linter': kubeLinter };

module.exports = {
  id: 'external-tools',
  label: 'Outils externes (optionnels)',
  category: O,
  controls: [
    'gitleaks : secrets (règles étendues)',
    'trivy : vulnérabilités, mauvaises configurations Dockerfile/Kubernetes/Helm, secrets',
    'osv-scanner : vulnérabilités et paquets malveillants depuis le lockfile',
    'hadolint : bonnes pratiques Dockerfile',
    'kube-linter : bonnes pratiques Kubernetes',
    'helm : rendu des templates (utilisé par le scanner Helm)',
  ],
  async run(ctx) {
    const findings = [];
    const notes = [];
    const used = [];
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-tools-'));
    for (const [name, fn] of Object.entries(RUNNERS)) {
      const bin = ctx.tools[name];
      if (!bin) continue;
      if (name === 'hadolint' && !ctx.files.some(f => /^dockerfile/i.test(f.base))) continue;
      if (name === 'kube-linter' && ctx.projectType !== 'helm') continue;
      // osv-scanner envoie la liste des paquets à api.osv.dev : jamais hors ligne, ni si des paquets internes sont déclarés.
      if (name === 'osv-scanner' && (ctx.offline || (ctx.config.npm.scopesInternes || []).length || (ctx.config.npm.paquetsInternesNonScopes || []).length)) { notes.push('osv-scanner non lancé (hors ligne ou paquets internes déclarés : la liste des paquets ne doit pas sortir).'); continue; }
      try {
        const r = await fn(bin, ctx, tmp);
        findings.push(...r);
        used.push(`${name} (${r.length} constat(s))`);
      } catch (e) { notes.push(`${name} : échec — ${e.message}`); }
    }
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
    const missing = Object.keys(RUNNERS).filter(n => !ctx.tools[n]);
    if (missing.length) notes.push('Outils absents (non bloquant) : ' + missing.join(', ') + '. Voir tools/setup-tools.ps1.');
    if (used.length) notes.push('Outils utilisés : ' + used.join(', '));
    return { findings, status: used.length ? 'ok' : 'non exécuté', notes, filesAnalyzed: 0 };
  },
};
