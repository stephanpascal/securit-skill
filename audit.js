#!/usr/bin/env node
'use strict';
/**
 * Audit de sécurité d'un projet (frontend Angular, BFF Node.js, chart Helm).
 *
 * Usage :
 *   node audit.js <nom> <url-gitlab> [options]
 *   node audit.js <nom> --path <dossier> [options]
 * Plusieurs projets : node audit-lot.js (voir son aide).
 *
 * Aucune commande du projet analysé n'est exécutée (pas de npm install).
 */
const { runAudit } = require('./lib/runner');
const { sanitizeText } = require('./lib/sanitize');
const { parseArgs, OPTIONS_HELP, isUrl, nameFromUrl } = require('./lib/cli');

const HELP = `
Audit de sécurité — skill-analyse

Usage :
  node audit.js <url-gitlab> [options]          (le nom est déduit de l'URL)
  node audit.js <nom> <url-gitlab> [options]
  node audit.js <nom> --path <dossier> [options]
  node audit-lot.js <url1> <url2> ...           (plusieurs projets, voir node audit-lot.js --help)

${OPTIONS_HELP}
`;

(async () => {
  let opts;
  try { opts = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message + '\n' + HELP); process.exit(1); }
  if (opts.diagnostic) {
    const { runDiagnostic } = require('./lib/diagnostic');
    const d = await runDiagnostic({ url: opts._.find(isUrl), offline: opts.offline, config: opts.config });
    console.log(d.text);
    process.exit(d.errors ? 1 : 0);
  }
  if (isUrl(opts._[0])) { opts.url = opts._[0]; opts.name = nameFromUrl(opts._[0]); } // node audit.js <url>
  else { opts.name = opts._[0]; opts.url = opts._[1]; }
  if (opts.help || !opts.name || (!opts.url && !opts.path)) { console.log(HELP); process.exit(opts.help ? 0 : 1); }
  try {
    const { res, paths, failed } = await runAudit(opts);
    const n = res.notation;
    console.log(`NOTE ${n.note} — risque ${n.risque} — score ${n.score}/100 — critiques ${n.compte.critical}, élevés ${n.compte.high}, moyens ${n.compte.medium}, faibles ${n.compte.low}`);
    console.log(`RESUME   ${paths.resume}`);
    console.log(`RAPPORT  ${paths.rapport}`);
    console.log(`VERIFIER ${paths.aVerifier}`);
    console.log(`JSON     ${paths.json}`);
    process.exit(opts.ci && failed ? 2 : 0);
  } catch (e) {
    console.error('ERREUR : ' + sanitizeText(e.stderr ? String(e.stderr).trim() : e.message));
    process.exit(1);
  }
})();
