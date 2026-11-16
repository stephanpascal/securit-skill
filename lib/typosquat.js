'use strict';
const path = require('path');
const { levenshtein } = require('./util');

const data = require(path.join(__dirname, '..', 'rules', 'paquets-populaires.json'));
const POPULAR = new Set(data.paquets);
const POPULAR_UNSCOPED = data.paquets.filter(p => !p.startsWith('@'));
const POPULAR_SCOPES = data.scopesPopulaires;

function isTransposition(a, b) {
  if (a.length !== b.length) return false;
  const diff = [];
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diff.push(i);
  return diff.length === 2 && diff[1] === diff[0] + 1 && a[diff[0]] === b[diff[1]] && a[diff[1]] === b[diff[0]];
}

/** Retourne le paquet populaire imité, ou null. */
function typosquatTarget(name) {
  if (!name || POPULAR.has(name)) return null;
  if (name.startsWith('@')) {
    const [scope, base] = name.split('/');
    if (POPULAR_SCOPES.includes(scope)) return null;
    for (const s of POPULAR_SCOPES) {
      if (s.length >= 5 && levenshtein(scope, s) === 1) return `${s}/${base}`;
    }
    return null;
  }
  if (name.length < 5) return null;
  const norm = name.replace(/[-_.]/g, '');
  for (const p of POPULAR_UNSCOPED) {
    if (p.length < 5) continue;
    if (norm === p.replace(/[-_.]/g, '') && name !== p) return p;
    const d = levenshtein(name, p);
    if (isTransposition(name, p)) return p;
    if (d === 1 || (d === 2 && p.length > 8 && name.length > 8)) return p;
    if (name === p + 'js' || name === p + '-js' || name === 'node-' + p || name === p + '2') return p;
  }
  return null;
}

module.exports = { typosquatTarget, POPULAR };
