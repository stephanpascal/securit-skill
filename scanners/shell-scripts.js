'use strict';
const { scanText } = require('../lib/patterns');
const { SHELL_RULES } = require('../lib/shell-rules');
const { makeFinding } = require('../lib/finding');

const R_HOOK = { id: 'SHELL_HOOK_GIT', sev: 'low', cat: 'shell', review: true, title: 'Hook git versionné (husky / lefthook…)', desc: 'Ce script s\'exécute automatiquement sur le poste de chaque développeur (commit, push, checkout) : vecteur d\'attaque discret.', fix: 'Relire le contenu du hook ; il ne doit lancer que des outils de qualité (lint, tests).' };
const R_HOOK_NET = { id: 'SHELL_HOOK_RESEAU', sev: 'high', cat: 'shell', review: true, title: 'Hook git effectuant un accès réseau', desc: 'Un hook exécuté sur les postes des développeurs contacte le réseau.', fix: 'Supprimer l\'accès réseau du hook.' };

const SCRIPT_EXT = new Set(['.sh', '.bash', '.zsh', '.ksh', '.ps1', '.psm1', '.bat', '.cmd', '.vbs']);

module.exports = {
  id: 'shell-scripts',
  label: 'Scripts shell et hooks git',
  category: 'shell',
  controls: [
    'Scripts .sh / .ps1 / .bat / .cmd, Makefile, fichiers avec shebang',
    'Hooks git versionnés (.husky, .githooks, lefthook) exécutés sur les postes développeurs',
    'Mêmes motifs dangereux que pour les Dockerfile (curl | sh, reverse shell, persistance, exfiltration…)',
  ],
  async run(ctx) {
    const findings = [];
    let count = 0;
    for (const file of ctx.files) {
      const isHook = /^(\.husky|\.githooks|\.git-hooks|\.config\/husky)\//.test(file.rel) && !/\/_\//.test(file.rel) || /^lefthook\.ya?ml$|^\.pre-commit-config\.ya?ml$/.test(file.rel);
      let isScript = SCRIPT_EXT.has(file.ext) || file.base === 'Makefile' || isHook;
      let text = null;
      if (!isScript && !file.ext && file.size < 200000) {
        text = ctx.readText(file);
        if (text && text.startsWith('#!')) isScript = true;
      }
      if (!isScript) continue;
      text = text || ctx.readText(file);
      if (!text) continue;
      count++;
      const fs = scanText(text, SHELL_RULES, { file: file.rel, category: 'shell', projectType: ctx.projectType });
      findings.push(...fs);
      if (isHook) {
        const net = /\b(curl|wget|Invoke-WebRequest|nc|ssh|scp|fetch\(|https?:\/\/)/.exec(text);
        findings.push(makeFinding(net ? R_HOOK_NET : R_HOOK, { file: file.rel, evidence: (net ? text.split(/\r?\n/).find(l => net[0] && l.includes(net[0])) : text.split(/\r?\n/).filter(l => l.trim() && !l.startsWith('#')).slice(0, 2).join(' ; ')) || file.rel }));
      }
    }
    return { findings, filesAnalyzed: count, notes: [] };
  },
};
