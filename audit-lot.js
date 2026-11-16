#!/usr/bin/env node
'use strict';
/**
 * Audit de plusieurs projets à la suite, avec une synthèse consolidée.
 *
 * Usage :
 *   node audit-lot.js <nom1> <url1> <nom2> <url2> ... [options communes]
 *   node audit-lot.js --fichier projets.txt [options communes]
 *
 * Fichier : une ligne par projet « nom url [options propres] » (ou « nom;url;options »), # pour commenter.
 */
const fs = require('fs');
const path = require('path');
const { runAudit } = require('./lib/runner');
const { parseArgs, splitLine, OPTIONS_HELP } = require('./lib/cli');
const { sanitizeText, sanitizeUrl } = require('./lib/sanitize');
const { writeBatchReport } = require('./lib/report');
const { ROOT } = require('./lib/config');
const { nowStamp } = require('./lib/util');

const HELP = `
Audit de sécurité — plusieurs projets

Usage :
  node audit-lot.js <nom1> <url1> <nom2> <url2> ... [options communes]
  node audit-lot.js --fichier projets.txt [options communes]

Fichier de projets (voir projets.exemple.txt) : une ligne par projet
  nom  url  [options propres au projet, ex. --ref 2.3.1 --type helm]
Les options communes s'appliquent à tous les projets ; celles d'une ligne les complètent ou les remplacent.

${OPTIONS_HELP}
`;

function readProjectFile(file) {
  const projects = [];
  const lines = fs.readFileSync(file, 'utf8').replace(/^﻿/, '').split(/\r?\n/);
  lines.forEach((raw, i) => {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) return;
    const fields = line.split(';').map(s => s.trim()).filter(Boolean);
    const tokens = line.includes(';') ? [fields[0], ...splitLine(fields.slice(1).join(' '))] : splitLine(line);
    const o = parseArgs(tokens);
    const [name, url] = o._;
    if (!name || (!url && !o.path)) throw new Error(`${file}:${i + 1} : ligne invalide (attendu « nom url [options] »)`);
    delete o._;
    projects.push(Object.assign(o, { name, url }));
  });
  return projects;
}

(async () => {
  let common;
  try { common = parseArgs(process.argv.slice(2), { extra: { '--fichier': 'fichier', '-f': 'fichier' } }); }
  catch (e) { console.error(e.message + '\n' + HELP); process.exit(1); }
  if (common.help) { console.log(HELP); process.exit(0); }

  let projects = [];
  try {
    if (common.fichier) projects = readProjectFile(path.resolve(common.fichier));
    const pos = common._;
    if (pos.length % 2 !== 0) throw new Error('Les projets passés en arguments doivent être des paires « nom url ».');
    for (let i = 0; i < pos.length; i += 2) projects.push({ name: pos[i], url: pos[i + 1] });
  } catch (e) { console.error('ERREUR : ' + e.message); process.exit(1); }
  if (!projects.length) { console.log(HELP); process.exit(1); }

  const names = projects.map(p => p.name);
  const dup = names.find((n, i) => names.indexOf(n) !== i);
  if (dup) { console.error(`ERREUR : projet en double dans la liste : ${dup}`); process.exit(1); }

  const base = Object.assign({}, common);
  delete base._; delete base.fichier; delete base.help;
  const results = [];
  const t0 = Date.now();
  for (let i = 0; i < projects.length; i++) {
    const p = projects[i];
    const opts = Object.assign({}, base, p, { quiet: true });
    process.stderr.write(`[lot] ${i + 1}/${projects.length} ${p.name}…\n`);
    const ts = Date.now();
    try {
      const { res, paths, failed } = await runAudit(opts);
      const n = res.notation;
      const top = [...new Set(res.constats.filter(f => ['critical', 'high'].includes(f.severity)).map(f => f.title))].slice(0, 5);
      results.push({ nom: p.name, url: sanitizeUrl(p.url) || null, ref: opts.ref || null, type: res.projet.type, note: n.note, risque: n.risque, score: n.score, compte: n.compte, echecSeuil: failed, comparaison: res.comparaison ? { note: res.comparaison.notePrecedente, score: res.comparaison.scorePrecedent, nouveaux: res.comparaison.nouveaux.length } : null, principaux: top, partiels: res.scanners.filter(s => s.status !== 'ok' && s.status !== 'non applicable').map(s => s.label), resume: paths.resume, rapport: paths.rapport, aVerifier: paths.aVerifier, aJuger: res.constats.filter(f => f.needsReview && f.severity !== 'info').length, dureeSec: Math.round((Date.now() - ts) / 1000) });
      console.log(`${p.name.padEnd(24)} NOTE ${n.note}  score ${String(n.score).padStart(3)}  critiques ${n.compte.critical}  élevés ${n.compte.high}  RESUME ${paths.resume}`);
    } catch (e) {
      const msg = sanitizeText(e.stderr ? String(e.stderr).trim() : e.message).split(/\r?\n/)[0];
      results.push({ nom: p.name, url: sanitizeUrl(p.url) || null, erreur: msg });
      console.log(`${p.name.padEnd(24)} ERREUR ${msg}`);
    }
  }

  const outDir = path.join(path.resolve(common.out || path.join(ROOT, 'reports')), '_lots', nowStamp());
  const paths = writeBatchReport({ date: new Date().toISOString(), dureeSec: Math.round((Date.now() - t0) / 1000), options: base, projets: results }, outDir);
  console.log(`SYNTHESE ${paths.synthese}`);
  const anyFail = results.some(r => r.erreur || r.echecSeuil);
  process.exit(common.ci && anyFail ? 2 : 0);
})();
