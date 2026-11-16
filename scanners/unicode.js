'use strict';
/**
 * Caractères Unicode invisibles ou trompeurs dans TOUS les fichiers texte (pas seulement le code) :
 * - suites de sélecteurs de variante (U+FE00–FE0F, U+E0100–E01EF) : charge encodée invisible (GlassWorm, 2025) ;
 * - caractères « tags » (U+E0000–E007F) : texte invisible pour l'humain mais lu par les IA (injection de consignes) ;
 * - caractères bidirectionnels et de largeur nulle hors fichiers de code (fichiers d'instructions IA, YAML, JSON, Markdown…).
 * Les fichiers de code JS/TS sont déjà contrôlés pour les bidi / largeur nulle par le scanner "code source".
 */
const { makeFinding } = require('../lib/finding');
const { truncate } = require('../lib/util');

const U = 'code';
const R = {
  SELECTORS: { id: 'UNICODE_SELECTEURS_VARIANTE', sev: 'critical', cat: U, title: 'Suite de sélecteurs de variante Unicode invisibles (charge cachée)', desc: 'Une longue suite de caractères invisibles encode des données : technique du ver GlassWorm (2025) pour cacher du code exécutable qui n\'apparaît pas dans l\'éditeur.', fix: 'Supprimer ces caractères et rechercher le code qui les décode (codePointAt, fromCodePoint, eval…).' },
  TAGS: { id: 'UNICODE_CARACTERES_TAGS', sev: 'high', cat: U, title: 'Caractères Unicode « tags » invisibles', desc: 'Texte invisible pour un humain mais lu par les assistants IA : permet de cacher des consignes (injection) dans un fichier ou un commentaire.', fix: 'Supprimer ces caractères et vérifier le texte caché (décodé dans le constat).' },
  BIDI: { id: 'UNICODE_BIDI_HORS_CODE', sev: 'high', cat: U, review: true, title: 'Caractères bidirectionnels dans un fichier de configuration ou de documentation', desc: 'Ces caractères inversent l\'affichage du texte : la commande ou consigne affichée diffère de celle lue par la machine ou l\'IA.', fix: 'Supprimer ces caractères.' },
  ZW: { id: 'UNICODE_INVISIBLE_HORS_CODE', sev: 'medium', cat: U, review: true, title: 'Caractères de largeur nulle dans un fichier de configuration ou de documentation', desc: 'Caractères invisibles pouvant masquer une différence (nom de paquet, URL, consigne IA).', fix: 'Supprimer ces caractères.' },
};

const CODE_EXT = /\.(js|mjs|cjs|ts|mts|cts|jsx|tsx|vue|svelte)$/i;
const SKIP = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$|\.(min\.js|map)$/i;
// Suites : 4+ sélecteurs BMP consécutifs, ou 2+ sélecteurs supplémentaires (U+E0100–E01EF).
const SELECTOR_RUN = /[︀-️]{4,}|(?:\uDB40[\uDD00-\uDDEF]){2,}/;
const TAG_RUN = /(?:\uDB40[\uDC00-\uDC7F])+/;

function lineOf(text, idx) { return text.slice(0, idx).split('\n').length; }

function decodeTags(s) {
  let out = '';
  for (const ch of s) { const cp = ch.codePointAt(0); if (cp >= 0xE0020 && cp <= 0xE007E) out += String.fromCharCode(cp - 0xE0000); }
  return out;
}

module.exports = {
  id: 'unicode',
  label: 'Caractères Unicode invisibles (tous fichiers)',
  category: U,
  controls: [
    'Suites de sélecteurs de variante invisibles encodant une charge (GlassWorm)',
    'Caractères « tags » invisibles (consignes cachées pour les IA), texte caché décodé dans le constat',
    'Caractères bidirectionnels et de largeur nulle dans les fichiers non-code (instructions IA, YAML, JSON, Markdown, configs)',
  ],
  async run(ctx) {
    const findings = [];
    let count = 0;
    for (const file of ctx.files) {
      if (SKIP.test(file.rel)) continue;
      const text = ctx.readText(file);
      if (!text) continue;
      count++;
      let m;
      if ((m = SELECTOR_RUN.exec(text))) {
        const n = (text.match(/[︀-️]|\uDB40[\uDD00-\uDDEF]/g) || []).length;
        findings.push(makeFinding(R.SELECTORS, { file: file.rel, line: lineOf(text, m.index), evidence: `${n} sélecteurs de variante invisibles — ligne : ${truncate(text.split('\n')[lineOf(text, m.index) - 1].replace(/[︀-️]|\uDB40[\uDD00-\uDDEF]/g, ''), 120)}` }));
      }
      if ((m = TAG_RUN.exec(text))) {
        findings.push(makeFinding(R.TAGS, { file: file.rel, line: lineOf(text, m.index), evidence: `texte caché : « ${truncate(decodeTags(m[0]), 200)} »` }));
      }
      if (!CODE_EXT.test(file.base)) {
        if ((m = /[‪-‮⁦-⁩]/.exec(text))) findings.push(makeFinding(R.BIDI, { file: file.rel, line: lineOf(text, m.index), evidence: 'U+' + m[0].charCodeAt(0).toString(16).toUpperCase() + ' : ' + truncate(text.split('\n')[lineOf(text, m.index) - 1], 120) }));
        const body = text.replace(/^﻿/, '');
        if ((m = /[​-‍⁠᠎﻿]/.exec(body)) && !/\.(md|txt|html?)$/i.test(file.base)) findings.push(makeFinding(R.ZW, { file: file.rel, line: lineOf(body, m.index), evidence: 'U+' + m[0].charCodeAt(0).toString(16).toUpperCase() + ' : ' + truncate(body.split('\n')[lineOf(body, m.index) - 1], 120) }));
        else if (m && /(^|\/)(AGENTS|CLAUDE|GEMINI)\.md$|copilot-instructions|\.cursorrules|\.windsurfrules|\.clinerules|\/prompts\//i.test(file.rel)) findings.push(makeFinding(R.ZW, { file: file.rel, line: lineOf(body, m.index), severity: 'high', evidence: 'U+' + m[0].charCodeAt(0).toString(16).toUpperCase() + ' dans un fichier d\'instructions IA' }));
      }
    }
    return { findings, filesAnalyzed: count, notes: [] };
  },
};
