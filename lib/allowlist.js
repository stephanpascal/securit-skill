'use strict';
/**
 * Exclusions de faux positifs : allowlists/<nom-projet>.json
 * {
 *   "exclusions": [
 *     { "regle": "CODE_EVAL", "fichier": "src/legacy/**", "contient": "", "justification": "…", "expire": "2027-06-30" }
 *   ]
 * }
 * Une exclusion sans justification est ignorée (et signalée dans le rapport).
 */
const fs = require('fs');
const path = require('path');
const { ROOT } = require('./config');
const { globToRegex } = require('./util');

/** Cherche allowlists/<P1234_S5678_fe01>.json puis allowlists/<fe01>.json. */
function loadAllowlist(...names) {
  const p = names.filter(Boolean).map(n => path.join(ROOT, 'allowlists', `${n}.json`)).find(f => fs.existsSync(f));
  if (!p) return { path: null, entries: [], invalid: [] };
  const json = JSON.parse(fs.readFileSync(p, 'utf8').replace(/^﻿/, ''));
  const entries = []; const invalid = [];
  const today = new Date().toISOString().slice(0, 10);
  for (const e of json.exclusions || []) {
    if (!e.regle || !e.justification || String(e.justification).trim().length < 10) { invalid.push(Object.assign({ raison: 'règle ou justification (10 caractères min.) manquante' }, e)); continue; }
    if (e.expire && e.expire < today) { invalid.push(Object.assign({ raison: `expirée le ${e.expire}` }, e)); continue; }
    entries.push(Object.assign({}, e, { _re: e.fichier ? globToRegex(e.fichier) : null }));
  }
  return { path: p, entries, invalid };
}

function applyAllowlist(findings, allow) {
  const kept = []; const suppressed = [];
  for (const f of findings) {
    const e = allow.entries.find(x => (x.regle === '*' || x.regle === f.rule)
      && (!x._re || (f.file && x._re.test(f.file)))
      && (!x.contient || (f.evidence || '').includes(x.contient)));
    if (e) suppressed.push(Object.assign({}, f, { justification: e.justification }));
    else kept.push(f);
  }
  return { kept, suppressed };
}

module.exports = { loadAllowlist, applyAllowlist };
