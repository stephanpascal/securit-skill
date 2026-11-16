'use strict';
/**
 * Fonctions utilitaires communes (sans dépendance externe).
 */
const crypto = require('crypto');

function truncate(s, n = 200) {
  if (s == null) return '';
  s = String(s).replace(/\t/g, ' ').trim();
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/** Extrait une portion de ligne autour d'un index (utile pour les lignes minifiées très longues). */
function snippetAround(line, index, n = 200) {
  if (line.length <= n) return truncate(line, n);
  const start = Math.max(0, index - Math.floor(n / 3));
  return (start > 0 ? '…' : '') + line.slice(start, start + n).trim() + '…';
}

function sha1(s) {
  return crypto.createHash('sha1').update(String(s)).digest('hex');
}

function isIp(host) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
}

/** Hôte considéré comme interne : localhost, IP privée, nom de service k8s sans point, domaines internes configurés. */
function isInternalHost(host, internalDomains = []) {
  if (!host) return true;
  host = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host === '0.0.0.0' || host === '::1' || host === '::') return true;
  if (isIp(host)) {
    const p = host.split('.').map(Number);
    if (p[0] === 10 || p[0] === 127) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    return false; // 169.254.x (metadata cloud) volontairement non interne
  }
  if (!host.includes('.')) return true; // service kubernetes / docker compose
  if (/\.(svc|cluster\.local|local|internal|lan|intra|corp)$/.test(host) || host.includes('.svc.')) return true;
  return internalDomains.some(d => {
    d = String(d).toLowerCase().replace(/^\*?\./, '');
    return d && (host === d || host.endsWith('.' + d));
  });
}

const URL_RE = /\b(?:https?|wss?|ftp):\/\/[^\s'"`<>)\]}\\,;]+/gi;

function extractUrls(text) {
  return String(text).match(URL_RE) || [];
}

function hostOf(url) {
  const m = /^[a-z][a-z0-9+.-]*:\/\/(?:[^@\/\s]*@)?(\[[^\]]+\]|[^:\/\s?#]+)/i.exec(url);
  return m ? m[1].toLowerCase() : '';
}

function levenshtein(a, b) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 2) return 99;
  const prev = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = tmp;
    }
  }
  return prev[b.length];
}

/** Glob simple : ** (tout), * (hors /), ? */
function globToRegex(glob) {
  let re = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*') {
      if (glob[i + 1] === '*') { re += '.*'; i++; if (glob[i + 1] === '/') i++; }
      else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp('^' + re + '$', 'i');
}

function shannonEntropy(s) {
  const freq = {};
  for (const ch of s) freq[ch] = (freq[ch] || 0) + 1;
  let e = 0;
  for (const k in freq) { const p = freq[k] / s.length; e -= p * Math.log2(p); }
  return e;
}

/** Masque une valeur secrète : garde les 4 premiers caractères. */
function maskValue(v) {
  v = String(v);
  if (v.length <= 6) return '****';
  return v.slice(0, 4) + '****(masqué)';
}

function nowStamp(d = new Date()) {
  const p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}_${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

function daysAgo(n) {
  return new Date(Date.now() - n * 86400000);
}

function parsePort(s) {
  const m = /(?:^|[:\s\]])(\d{1,5})(?:\s|$|\/)/.exec(' ' + String(s).trim() + ' ');
  return m ? Number(m[1]) : null;
}

module.exports = {
  truncate, snippetAround, sha1, isIp, isInternalHost, extractUrls, hostOf, levenshtein,
  globToRegex, shannonEntropy, maskValue, nowStamp, daysAgo, parsePort, URL_RE,
};
