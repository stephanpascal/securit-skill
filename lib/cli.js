'use strict';
/**
 * Analyse des options de ligne de commande, partagée par audit.js et audit-lot.js.
 */

const OPTIONS_HELP = `Options :
  --type fe|bff|helm   Forcer le type de projet (sinon détecté par le contenu)
  --ref <branche|tag>  Branche ou tag à analyser (défaut : branche par défaut)
  --days <n>           Période d'historique git analysée (défaut : config git.periodeJours)
  --shallow            Clone superficiel (rapide, sans analyse de l'historique git)
  --offline            Aucun accès réseau (pas d'OSV, d'Artifactory ni d'API GitLab)
  --no-api             Ne pas interroger l'API GitLab
  --keep               Conserver le clone dans workspace/ après l'analyse
  --out <dossier>      Dossier des rapports (défaut : reports/)
  --config <fichier>   Fichier de configuration supplémentaire
  --no-save            Ne pas enregistrer cette analyse comme référence de comparaison
  --ci                 Code de sortie 2 si une note atteint le seuil (notation.seuilEchecCI)
  --quiet              Pas de messages de progression
  --help               Afficher cette aide

Variables d'environnement :
  GITLAB_TOKEN         Token GitLab (droit read_api) pour les contrôles MR / approbations / protections
  NPM_TOKEN            Token Artifactory (si le registre exige une authentification)
  HTTPS_PROXY, NO_PROXY, NODE_EXTRA_CA_CERTS   Proxy et certificat d'entreprise`;

/**
 * parseArgs(argv, { extra }) : extra = { '--fichier': 'fichier' } pour des options spécifiques avec valeur.
 */
function parseArgs(argv, { extra = {} } = {}) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { const v = argv[++i]; if (v === undefined) throw new Error(`Valeur manquante pour ${a}`); return v; };
    if (extra[a]) { o[extra[a]] = val(); continue; }
    switch (a) {
      case '--help': case '-h': o.help = true; break;
      case '--path': o.path = val(); break;
      case '--type': o.type = val(); break;
      case '--ref': o.ref = val(); break;
      case '--days': o.days = Number(val()); break;
      case '--shallow': o.shallow = true; break;
      case '--offline': o.offline = true; break;
      case '--no-api': o.noApi = true; break;
      case '--keep': o.keep = true; break;
      case '--out': o.out = val(); break;
      case '--config': o.config = val(); break;
      case '--no-save': o.noSave = true; break;
      case '--ci': o.ci = true; break;
      case '--quiet': o.quiet = true; break;
      default:
        if (a.startsWith('--')) throw new Error(`Option inconnue : ${a}`);
        o._.push(a);
    }
  }
  if (o.type && !['fe', 'bff', 'helm'].includes(o.type)) throw new Error('--type doit valoir fe, bff ou helm');
  if (o.days !== undefined && !(o.days > 0)) throw new Error('--days doit être un nombre positif');
  return o;
}

/** Découpe une ligne en arguments (gère les guillemets simples et doubles). */
function splitLine(line) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

module.exports = { parseArgs, splitLine, OPTIONS_HELP };
