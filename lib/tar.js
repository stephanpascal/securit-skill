'use strict';
/**
 * Lecture d'archives .tgz (paquets npm, charts Helm) en mémoire, sans rien écrire ni exécuter.
 */
const zlib = require('zlib');

function readStr(buf, start, len) {
  const s = buf.subarray(start, start + len);
  const z = s.indexOf(0);
  return (z >= 0 ? s.subarray(0, z) : s).toString('utf8');
}

/**
 * extractTgz(buffer, { maxFiles, maxEntrySize, filter(name) }) -> [{ name, content: Buffer }]
 */
function extractTgz(buffer, opts = {}) {
  const maxFiles = opts.maxFiles || 5000;
  const maxEntrySize = opts.maxEntrySize || 5 * 1024 * 1024;
  const data = zlib.gunzipSync(buffer, { maxOutputLength: 512 * 1024 * 1024 });
  const out = [];
  let off = 0;
  let longName = null;
  let paxPath = null;
  while (off + 512 <= data.length && out.length < maxFiles) {
    const header = data.subarray(off, off + 512);
    if (header.every(b => b === 0)) break;
    let name = readStr(header, 0, 100);
    const size = parseInt(readStr(header, 124, 12).trim() || '0', 8) || 0;
    const type = String.fromCharCode(header[156] || 48);
    const magic = readStr(header, 257, 6);
    if (magic.startsWith('ustar')) {
      const prefix = readStr(header, 345, 155);
      if (prefix) name = prefix + '/' + name;
    }
    const start = off + 512;
    const content = data.subarray(start, start + size);
    off = start + Math.ceil(size / 512) * 512;
    if (type === 'L') { longName = readStr(content, 0, content.length); continue; }
    if (type === 'x') {
      const m = /\d+ path=([^\n]+)\n/.exec(content.toString('utf8'));
      if (m) paxPath = m[1];
      continue;
    }
    if (type === 'g') continue;
    if (longName) { name = longName; longName = null; }
    if (paxPath) { name = paxPath; paxPath = null; }
    if (type !== '0' && type !== '\0' && type !== '7') continue; // fichiers réguliers uniquement
    if (size > maxEntrySize) { out.push({ name, content: null, size }); continue; }
    if (opts.filter && !opts.filter(name)) continue;
    out.push({ name, content: Buffer.from(content), size });
  }
  return out;
}

module.exports = { extractTgz };
