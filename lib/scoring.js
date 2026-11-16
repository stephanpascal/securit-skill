'use strict';
/**
 * Notation : score sur 100 et note de A à E.
 * - Chaque règle déclenchée retire des points selon sa sévérité ; les répétitions d'une même règle comptent de moins en moins (max x3).
 * - Plafonds : 1 constat critique => note D au mieux ; 3 règles critiques => E ; 3 règles élevées => C au mieux.
 */
const PENALTY = { critical: 30, high: 12, medium: 4, low: 1, info: 0 };
const GRADES = ['A', 'B', 'C', 'D', 'E'];
const RISK = { A: 'Faible', B: 'Modéré', C: 'Significatif', D: 'Élevé', E: 'Critique' };

function groups(findings) {
  const g = new Map();
  for (const f of findings) {
    const k = f.rule + '|' + f.severity;
    const n = 1 + ((f.extra && f.extra.occurrencesSupplementaires) || 0);
    if (!g.has(k)) g.set(k, { rule: f.rule, severity: f.severity, count: 0, category: f.category });
    g.get(k).count += n;
  }
  return [...g.values()];
}

function rawScore(findings) {
  let pen = 0;
  for (const gr of groups(findings)) pen += PENALTY[gr.severity] * (1 + 0.5 * Math.min(gr.count - 1, 4));
  return Math.max(0, Math.round(100 - pen));
}

function gradeOf(score) {
  return score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'E';
}

function worse(a, b) { return GRADES.indexOf(a) > GRADES.indexOf(b) ? a : b; }

function computeScore(findings) {
  const score = rawScore(findings);
  let grade = gradeOf(score);
  const gr = groups(findings);
  const crit = gr.filter(g => g.severity === 'critical').length;
  const high = gr.filter(g => g.severity === 'high').length;
  const caps = [];
  const g0 = grade;
  if (crit >= 3) { grade = worse(grade, 'E'); if (grade !== g0) caps.push(`${crit} règles critiques déclenchées → note E`); }
  else if (crit >= 1) { grade = worse(grade, 'D'); if (grade !== g0) caps.push(`${crit} règle(s) critique(s) déclenchée(s) → note D au mieux`); }
  if (high >= 3) { const before = grade; grade = worse(grade, 'C'); if (grade !== before) caps.push(`${high} règles de sévérité élevée → note C au mieux`); }
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const byCategory = {};
  for (const cat of [...new Set(findings.map(f => f.category))]) {
    const fs = findings.filter(f => f.category === cat);
    const s = rawScore(fs);
    let g = gradeOf(s);
    if (fs.some(f => f.severity === 'critical')) g = worse(g, 'D');
    byCategory[cat] = { score: s, note: g, constats: fs.length, critiques: fs.filter(f => f.severity === 'critical').length, eleves: fs.filter(f => f.severity === 'high').length };
  }
  return { score, note: grade, risque: RISK[grade], plafonds: caps, compte: counts, parCategorie: byCategory };
}

function failsThreshold(grade, threshold) {
  return GRADES.indexOf(grade) >= GRADES.indexOf(threshold || 'D');
}

module.exports = { computeScore, failsThreshold, GRADES, RISK, PENALTY };
