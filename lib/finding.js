'use strict';
/**
 * Format commun d'un constat (finding) produit par tous les scanners.
 */
const { sha1, truncate } = require('./util');

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_FR = { critical: 'Critique', high: 'Élevé', medium: 'Moyen', low: 'Faible', info: 'Info' };
const SEV_ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: '⚪' };

const CATEGORIES = {
  docker: 'Dockerfile',
  shell: 'Scripts shell et hooks',
  code: 'Code source',
  serveur: 'Configuration serveur (nginx / apache / autres)',
  package: 'package.json et configuration npm',
  dependances: 'Dépendances (lockfile, scripts d\'installation, CVE)',
  k8s: 'Helm / Kubernetes / CI',
  secrets: 'Secrets',
  ide: 'IDE et assistants IA (exécution automatique, MCP, instructions IA)',
  structure: 'Structure du dépôt',
  git: 'Historique git',
  gitlab: 'GitLab (merge requests, protections)',
  outils: 'Outils externes',
};

/**
 * Crée un constat à partir d'une règle et des données de contexte.
 * rule : { id, sev, cat, title, desc, fix, review }
 */
function makeFinding(rule, data = {}) {
  const f = {
    rule: rule.id,
    title: data.title || rule.title,
    severity: data.severity || rule.sev,
    category: data.category || rule.cat,
    file: data.file || null,
    line: data.line || null,
    evidence: data.evidence != null ? truncate(data.evidence, 300) : null,
    description: data.description || rule.desc || '',
    recommendation: data.recommendation || rule.fix || '',
    needsReview: data.needsReview != null ? !!data.needsReview : !!rule.review,
    source: data.source || 'interne',
  };
  if (data.extra) f.extra = data.extra;
  f.fingerprint = sha1([f.rule, f.file || '', (f.evidence || '').replace(/\s+/g, ' ')].join('|')).slice(0, 16);
  return f;
}

function sevRank(s) {
  const i = SEVERITIES.indexOf(s);
  return i < 0 ? 99 : i;
}

function sortFindings(list) {
  return list.sort((a, b) => sevRank(a.severity) - sevRank(b.severity)
    || (a.category || '').localeCompare(b.category || '')
    || (a.file || '').localeCompare(b.file || '')
    || (a.line || 0) - (b.line || 0));
}

module.exports = { SEVERITIES, SEV_FR, SEV_ICON, CATEGORIES, makeFinding, sevRank, sortFindings };
