'use strict';
/**
 * Parcours des fichiers du dépôt analysé, avec lecture paresseuse et cache.
 * Les liens symboliques ne sont jamais suivis (un lien pourrait pointer hors du dépôt).
 */
const fs = require('fs');
const path = require('path');

// Dossiers dont le contenu n'est pas analysé (mais leur présence est signalée par le scanner "structure").
const SKIP_CONTENT_DIRS = new Set(['.git', 'node_modules', '.angular', '.nx', '.cache', 'coverage', '.turbo', '.parcel-cache']);

function walk(root, { maxFileSize = 2 * 1024 * 1024, maxFiles = 50000 } = {}) {
  const files = [];
  const skippedDirs = [];
  const symlinks = [];
  const stack = [''];
  while (stack.length) {
    const relDir = stack.pop();
    let entries;
    try { entries = fs.readdirSync(path.join(root, relDir), { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const rel = relDir ? relDir + '/' + e.name : e.name;
      if (e.isSymbolicLink()) { symlinks.push(rel); continue; }
      if (e.isDirectory()) {
        if (SKIP_CONTENT_DIRS.has(e.name)) { skippedDirs.push(rel); continue; }
        stack.push(rel);
      } else if (e.isFile()) {
        if (files.length >= maxFiles) continue;
        let size = 0;
        try { size = fs.statSync(path.join(root, rel)).size; } catch { /* ignore */ }
        const base = e.name;
        const dot = base.lastIndexOf('.');
        files.push({ rel, abs: path.join(root, rel), base, ext: dot > 0 ? base.slice(dot).toLowerCase() : '', size, tooLarge: size > maxFileSize });
      }
    }
  }
  files.sort((a, b) => a.rel.localeCompare(b.rel));
  return { files, skippedDirs, symlinks };
}

/** Crée un lecteur avec cache ; retourne null pour un binaire ou un fichier trop gros. */
function makeReader() {
  const cache = new Map();
  return function readText(file) {
    if (cache.has(file.rel)) return cache.get(file.rel);
    let txt = null;
    if (!file.tooLarge) {
      try {
        const buf = fs.readFileSync(file.abs);
        const probe = buf.subarray(0, 8000);
        if (!probe.includes(0)) txt = buf.toString('utf8');
      } catch { /* ignore */ }
    }
    cache.set(file.rel, txt);
    return txt;
  };
}

function isBinary(file, readText) {
  return !file.tooLarge && readText(file) === null;
}

module.exports = { walk, makeReader, isBinary, SKIP_CONTENT_DIRS };
