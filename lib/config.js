'use strict';
/**
 * Chargement de la configuration : config/settings.json puis surcharge par config/settings.local.json.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');

function deepMerge(a, b) {
  if (Array.isArray(b) || typeof b !== 'object' || b === null) return b;
  const out = Object.assign({}, a);
  for (const k of Object.keys(b)) out[k] = (k in out && typeof out[k] === 'object' && !Array.isArray(out[k])) ? deepMerge(out[k], b[k]) : b[k];
  return out;
}

function readJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8').replace(/^﻿/, ''));
}

function loadConfig(customPath) {
  let cfg = readJson(path.join(ROOT, 'config', 'settings.json'));
  const local = path.join(ROOT, 'config', 'settings.local.json');
  if (fs.existsSync(local)) cfg = deepMerge(cfg, readJson(local));
  if (customPath) cfg = deepMerge(cfg, readJson(path.resolve(customPath)));

  // Normalisation des registres autorisés : Artifactory est toujours autorisé s'il est renseigné.
  const regs = new Set((cfg.npm.registresAutorises || []).map(normalizeRegistry));
  if (cfg.npm.artifactoryUrl) regs.add(normalizeRegistry(cfg.npm.artifactoryUrl));
  cfg.npm.registresAutorises = [...regs].filter(Boolean);
  cfg.npm.registreRequetes = normalizeRegistry(cfg.npm.artifactoryUrl) || 'https://registry.npmjs.org/';
  return cfg;
}

function normalizeRegistry(u) {
  if (!u) return '';
  u = String(u).trim();
  return u.endsWith('/') ? u : u + '/';
}

module.exports = { loadConfig, ROOT, normalizeRegistry };
