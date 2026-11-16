'use strict';
/**
 * Protection contre les fuites dans les rapports, les journaux et le contexte de l'IA :
 * - masquage de tout ce qui ressemble à un secret, dans toutes les chaînes du résultat (constats, extraits, inventaire) ;
 * - suppression des identifiants éventuellement présents dans une URL (https://user:token@hote).
 */
const { maskValue } = require('./util');

// Motifs de secrets forts (mêmes familles que le scanner "secrets"), en mode global.
const SECRET_PATTERNS = [
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END[^-]*-----|$)/g,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  /\b(?:glpat|gldt|glrt|glptt|glsoat|glcbt|glffct|glimt|glagent)-[0-9A-Za-z_-]{20,}/g,
  /\bGR1348941[0-9A-Za-z_-]{20,}/g,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{60,}/g,
  /\bnpm_[0-9A-Za-z]{36}\b/g,
  /\bxox[abposr]-[0-9A-Za-z-]{10,}/g,
  /\bAIza[0-9A-Za-z_-]{35}\b/g,
  /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}/g,
  /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /AccountKey=[A-Za-z0-9+/=]{40,}/g,
];
// Clé=valeur sensibles : seule la valeur est masquée.
const KV_PATTERN = /((?:_authToken|_auth|_password|password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|token)["']?\s*[:=]\s*["']?)([^\s"',;}{$<>]{6,})/gi;
const URL_CREDS = /\b([a-z][a-z0-9+.-]*:\/\/)([^\s:@/'"<>]+):([^\s@/'"<>]+)@/gi;

function maskString(s) {
  if (typeof s !== 'string' || s.length < 6) return s;
  let out = s;
  for (const re of SECRET_PATTERNS) out = out.replace(re, m => (m.includes('(masqué)') ? m : maskValue(m)));
  out = out.replace(KV_PATTERN, (m, k, v) => (v.includes('(masqué)') || /^\*+$/.test(v) ? m : k + maskValue(v)));
  out = out.replace(URL_CREDS, (m, proto, user) => `${proto}${user}:****@`);
  return out;
}

function maskDeep(value) {
  if (typeof value === 'string') return maskString(value);
  if (Array.isArray(value)) return value.map(maskDeep);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = maskDeep(v);
    return out;
  }
  return value;
}

/** Retire les identifiants d'une URL (https://user:token@hote/... -> https://hote/...). */
function sanitizeUrl(url) {
  if (!url) return url;
  return String(url).replace(/^([a-z][a-z0-9+.-]*:\/\/)[^@/\s]+@/i, '$1');
}

/** Masque les identifiants d'URL dans un texte libre (messages d'erreur git, journaux). */
function sanitizeText(text) {
  return String(text || '').replace(URL_CREDS, (m, proto) => `${proto}****@`);
}

module.exports = { maskString, maskDeep, sanitizeUrl, sanitizeText };
