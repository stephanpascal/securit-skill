'use strict';
/**
 * Moteur de règles par motifs (regex), ligne par ligne.
 *
 * Une règle : {
 *   id, sev, cat, title, desc, fix, review,
 *   re: RegExp,                 // motif recherché
 *   exclude?: RegExp,           // motif d'exclusion sur la même ligne
 *   filter?: (line, match, opts) => boolean | {severity?, evidence?, description?}
 *   sevByType?: { fe: 'critical', ... }   // sévérité selon le type de projet
 *   mask?: true                 // masquer la valeur (secrets)
 * }
 */
const { makeFinding } = require('./finding');
const { snippetAround, maskValue } = require('./util');

function toLines(text, offset = 0) {
  return String(text).split(/\r?\n/).map((t, i) => ({ n: i + 1 + offset, text: t }));
}

function maskLine(line, re) {
  const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  return line.replace(g, m => maskValue(m));
}

/**
 * Applique les règles sur un tableau de lignes { n, text }.
 * opts : { file, category, projectType, maxPerRule (5), evidencePrefix, internalDomains }
 */
function scanLines(lines, rules, opts = {}) {
  const maxPerRule = opts.maxPerRule || 5;
  const out = [];
  const counts = new Map();
  const firsts = new Map();
  for (const { n, text } of lines) {
    if (!text || text.length < 2) continue;
    for (const rule of rules) {
      const m = rule.re.exec(text);
      if (!m) continue;
      if (rule.exclude && rule.exclude.test(text)) continue;
      let override = {};
      if (rule.filter) {
        const r = rule.filter(text, m, opts);
        if (!r) continue;
        if (typeof r === 'object') override = r;
      }
      const c = (counts.get(rule.id) || 0) + 1;
      counts.set(rule.id, c);
      if (c > maxPerRule) continue;
      let ev = override.evidence || snippetAround(text, m.index);
      if (rule.mask) ev = maskLine(ev, rule.re);
      if (opts.evidencePrefix) ev = opts.evidencePrefix + ev;
      const severity = override.severity
        || (rule.sevByType && opts.projectType && rule.sevByType[opts.projectType])
        || rule.sev;
      const f = makeFinding(rule, {
        file: opts.file,
        line: n,
        evidence: ev,
        severity,
        category: opts.category || rule.cat,
        description: override.description,
        needsReview: override.needsReview,
      });
      if (!firsts.has(rule.id)) firsts.set(rule.id, f);
      out.push(f);
    }
  }
  for (const [id, c] of counts) {
    if (c > maxPerRule) {
      const f = firsts.get(id);
      f.extra = Object.assign({}, f.extra, { occurrencesSupplementaires: c - maxPerRule });
    }
  }
  return out;
}

function scanText(text, rules, opts = {}) {
  return scanLines(toLines(text, opts.lineOffset || 0), rules, opts);
}

module.exports = { scanLines, scanText, toLines };
