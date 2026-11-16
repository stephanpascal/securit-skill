'use strict';
/**
 * Orchestration d'une analyse complète.
 */
const fs = require('fs');
const path = require('path');
const { loadConfig, ROOT } = require('./config');
const { walk, makeReader } = require('./fswalk');
const { cloneRepo, repoInfo, removeDir, parseGitlabUrl } = require('./clone');
const { detectType, TYPE_LABEL } = require('./detect');
const { detectTools, networkDiagnostic } = require('./env');
const { loadAllowlist, applyAllowlist } = require('./allowlist');
const { computeScore, failsThreshold } = require('./scoring');
const { writeReports } = require('./report');
const { sortFindings } = require('./finding');
const { nowStamp } = require('./util');
const { maskDeep, sanitizeUrl } = require('./sanitize');

const VERSION = require(path.join(ROOT, 'package.json')).version;

const SCANNERS = [
  require('../scanners/structure'),
  require('../scanners/secrets'),
  require('../scanners/dockerfile'),
  require('../scanners/shell-scripts'),
  require('../scanners/source-code'),
  require('../scanners/unicode'),
  require('../scanners/ide-ai'),
  require('../scanners/server-config'),
  require('../scanners/package-json'),
  require('../scanners/dependencies'),
  require('../scanners/k8s-helm'),
  require('../scanners/git-local'),
  require('../scanners/gitlab-api'),
  require('../scanners/external-tools'),
];

function mergeInventory(target, inv) {
  for (const [k, v] of Object.entries(inv || {})) {
    if (Array.isArray(v)) target[k] = (target[k] || []).concat(v);
    else if (v && typeof v === 'object') target[k] = Object.assign(target[k] || {}, v);
    else target[k] = v;
  }
}

function excerpt(root, f, radius = 4) {
  if (!f.file || !f.line) return null;
  const p = path.join(root, f.file);
  try {
    if (!fs.statSync(p).isFile()) return null;
    const lines = fs.readFileSync(p, 'utf8').split(/\r?\n/);
    const s = Math.max(0, f.line - 1 - radius);
    const e = Math.min(lines.length, f.line + radius);
    return lines.slice(s, e).map((l, i) => `${String(s + i + 1).padStart(5)}${s + i + 1 === f.line ? ' >' : '  '} ${l.length > 300 ? l.slice(0, 300) + '…' : l}`).join('\n');
  } catch { return null; }
}

function safeName(n) { return String(n).replace(/[^\w.-]+/g, '_').slice(0, 80); }

async function runAudit(options) {
  const t0 = Date.now();
  const log = options.quiet ? () => {} : (m => process.stderr.write(`[audit] ${m}\n`));
  const config = loadConfig(options.config);
  const name = safeName(options.name || (options.path ? path.basename(path.resolve(options.path)) : 'projet'));
  const reportsBase = path.resolve(options.out || path.join(ROOT, 'reports'));
  const previousPath = path.join(reportsBase, name, 'derniere-analyse.json');
  let previous = null;
  try { previous = JSON.parse(fs.readFileSync(previousPath, 'utf8')); } catch { /* première analyse */ }

  // 1. Source
  let root; let cloned = false;
  const gitlab = options.url ? parseGitlabUrl(options.url) : null;
  if (options.path) {
    root = path.resolve(options.path);
    if (!fs.existsSync(root)) throw new Error('Dossier introuvable : ' + root);
  } else if (options.url) {
    root = path.join(ROOT, 'workspace', `${name}-${nowStamp()}`);
    cloneRepo(options.url, root, { ref: options.ref, shallow: options.shallow, log });
    cloned = true;
  } else throw new Error('Indiquer une URL GitLab ou --path <dossier>.');

  try {
    const repo = repoInfo(root);
    log(`Parcours des fichiers de ${root}…`);
    const { files, skippedDirs, symlinks } = walk(root, { maxFileSize: config.analyse.tailleMaxFichierKo * 1024 });
    const readText = makeReader();
    const detection = detectType(files, readText, name, options.type);
    log(`Type détecté : ${TYPE_LABEL[detection.type]} (${detection.reasons.join(', ') || 'nom'})`);
    const tools = detectTools();
    const network = await networkDiagnostic(config, { offline: options.offline, gitlabHost: gitlab && gitlab.host });
    if (!options.offline) log(`Réseau : OSV ${network.osv ? 'ok' : 'KO'}, registre ${network.registre ? 'ok' : 'KO'}, GitLab ${network.gitlab ? 'ok' : 'KO'}`);
    const offline = options.offline || (!network.osv && !network.registre && !network.gitlab);

    const ctx = {
      root, files, skippedDirs, symlinks, readText, config, options, repo, previous, tools, network, offline,
      projectType: detection.type, gitlab, gitlabHost: gitlab ? gitlab.host : (config.gitlab.url ? new URL(config.gitlab.url).host : null),
      profil: (config.profils || {})[detection.type] || {},
    };

    // 2. Scanners
    let findings = [];
    const scanners = [];
    const inventory = {};
    let gitSnapshot = null;
    for (const sc of SCANNERS) {
      const ts = Date.now();
      log(`Analyse : ${sc.label}…`);
      let r;
      try { r = await sc.run(ctx); }
      catch (e) { r = { findings: [], status: 'erreur', notes: ['Erreur : ' + e.message] }; }
      if (sc.id === 'git-local') {
        gitSnapshot = r.gitSnapshot || null;
        ctx.gitCandidates = (r.inventory && r.inventory.git && r.inventory.git.commitsDirects) || [];
      }
      if (sc.id === 'gitlab-api' && r.checkedShas && r.checkedShas.length) {
        // Les commits vérifiés appartenant à une MR ne sont pas des pushs directs (merge fast-forward / squash).
        const confirmed = new Set(r.confirmedDirect || []);
        const checked = new Set(r.checkedShas);
        findings = findings.filter(f => !(f.rule === 'GIT_COMMIT_DIRECT_PROBABLE' && f.extra && checked.has(f.extra.sha) && !confirmed.has(f.extra.sha)));
      }
      findings.push(...(r.findings || []));
      mergeInventory(inventory, r.inventory);
      scanners.push({ id: sc.id, label: sc.label, category: sc.category, controls: sc.controls, status: r.status || 'ok', filesAnalyzed: r.filesAnalyzed, notes: r.notes || [], constats: (r.findings || []).length, dureeMs: Date.now() - ts });
    }

    // 3. Dédoublonnage
    const seen = new Set();
    findings = findings.filter(f => { const k = `${f.rule}|${f.file}|${f.line}|${f.evidence}`; if (seen.has(k)) return false; seen.add(k); return true; });

    // 3 bis. Profil du type de projet : règles ramenées à Info (hors note) et regroupées en un constat par règle
    const informatives = new Set(ctx.profil.reglesInformatives || []);
    const profilNotes = [];
    if (informatives.size) {
      const grouped = new Map();
      findings = findings.filter(f => {
        if (!informatives.has(f.rule)) return true;
        if (!grouped.has(f.rule)) grouped.set(f.rule, []);
        grouped.get(f.rule).push(f);
        return false;
      });
      for (const [rule, list] of grouped) {
        const f = Object.assign({}, list[0]);
        const n = list.reduce((a, x) => a + 1 + ((x.extra && x.extra.occurrencesSupplementaires) || 0), 0);
        f.severity = 'info';
        f.needsReview = false;
        f.description = `${f.description} — Profil « ${detection.type} » : surveillance allégée, constat informatif non compté dans la note.`;
        if (n > 1) f.extra = Object.assign({}, f.extra, { occurrencesSupplementaires: n - 1, exemples: list.slice(1, 6).map(x => x.evidence) });
        findings.push(f);
        profilNotes.push(`${rule} (${n})`);
      }
    }

    // 4. Exclusions
    const allow = loadAllowlist(name);
    const { kept, suppressed } = applyAllowlist(findings, allow);
    findings = sortFindings(kept);

    // 5. Extraits de code pour les points à juger
    const maxEx = config.analyse.extraitsAVerifier;
    findings.filter(f => f.needsReview && f.severity !== 'info').slice(0, maxEx).forEach(f => { const ex = excerpt(root, f); if (ex) f.extrait = ex; });

    // 6. Notation et comparaison
    const notation = computeScore(findings);
    let comparaison = null;
    if (previous && previous.constats) {
      const prevFp = new Set(previous.constats.map(f => f.fingerprint));
      const curFp = new Set(findings.map(f => f.fingerprint));
      comparaison = {
        date: previous.analyse.date, notePrecedente: previous.notation.note, scorePrecedent: previous.notation.score,
        nouveaux: findings.filter(f => !prevFp.has(f.fingerprint)).map(f => ({ rule: f.rule, title: f.title, severity: f.severity, file: f.file, line: f.line })),
        resolus: previous.constats.filter(f => !curFp.has(f.fingerprint)).map(f => ({ rule: f.rule, title: f.title, severity: f.severity, file: f.file, line: f.line })),
      };
    }

    const stamp = nowStamp();
    const outDir = path.join(reportsBase, name, stamp);
    const res = {
      outil: { nom: 'skill-analyse', version: VERSION },
      projet: { nom: name, url: sanitizeUrl(options.url) || null, chemin: options.path ? root : null, type: detection.type, typeLibelle: TYPE_LABEL[detection.type], detection, branche: repo.branch || null, commit: repo.commit || null, dateCommit: repo.commitDate || null },
      analyse: {
        date: new Date().toISOString(), dureeSec: Math.round((Date.now() - t0) / 1000), mode: offline ? 'hors ligne' : 'en ligne', reseau: network,
        outils: Object.fromEntries(Object.entries(tools).map(([k, v]) => [k, !!v])), fichiers: files.length, maxExtraits: maxEx,
        options: { ref: options.ref || null, jours: options.days || config.git.periodeJours, superficiel: !!options.shallow, sansApi: !!options.noApi },
        profil: { type: detection.type, reglesInformatives: [...informatives], ramenesAInfo: profilNotes, verifierCommitsSansMR: ctx.profil.verifierCommitsSansMR !== false },
        dossierRapport: outDir,
      },
      notation,
      constats: findings,
      ignores: suppressed,
      exclusionsInvalides: allow.invalid.map(e => { const c = Object.assign({}, e); delete c._re; return c; }),
      scanners,
      inventaire: inventory,
      comparaison,
      git: { refs: gitSnapshot || (previous && previous.git && previous.git.refs) || null },
    };

    // Masquage global des secrets avant toute écriture (rapports lus par l'IA, JSON, référence de comparaison)
    const safeRes = maskDeep(res);
    const paths = writeReports(safeRes, outDir);
    if (!options.noSave) {
      fs.mkdirSync(path.dirname(previousPath), { recursive: true });
      fs.copyFileSync(paths.json, previousPath);
    }
    const failed = failsThreshold(notation.note, config.notation.seuilEchecCI);
    return { res: safeRes, paths, failed, root, cloned };
  } finally {
    if (cloned && !options.keep) {
      log('Suppression du clone…');
      if (!removeDir(root)) log('⚠️ Impossible de supprimer entièrement ' + root);
    }
  }
}

module.exports = { runAudit, SCANNERS, VERSION };
