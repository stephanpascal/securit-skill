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
  --produit <P1234>    Code produit (sinon lu dans l'URL : segment pXXXX)
  --solution <S5678>   Code solution (sinon lu dans l'URL : segment sXXXX)
  --diagnostic [url]   Vérifier que le poste est prêt (logiciels, configuration, réseau, token, accès au projet)
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
      case '--diagnostic': o.diagnostic = true; break;
      case '--produit': o.produit = val().toUpperCase(); break;
      case '--solution': o.solution = val().toUpperCase(); break;
      default:
        if (a.startsWith('--')) throw new Error(`Option inconnue : ${a}`);
        o._.push(a);
    }
  }
  if (o.type && !['fe', 'bff', 'helm'].includes(o.type)) throw new Error('--type doit valoir fe, bff ou helm');
  if (o.days !== undefined && !(o.days > 0)) throw new Error('--days doit être un nombre positif');
  return o;
}

const URL_TOKEN = /^(https?:\/\/|ssh:\/\/|[\w.-]+@[\w.-]+:)/i;
function isUrl(s) { return URL_TOKEN.test(String(s || '')); }

/** Nom de projet déduit de l'URL : https://gitlab/equipe/fe01.git -> fe01 */
function nameFromUrl(url) {
  const p = String(url).replace(/\.git\/?$/, '').replace(/\/+$/, '').split(/[/:]/).filter(Boolean);
  return p[p.length - 1] || 'projet';
}

/**
 * Codes de l'entreprise présents dans le chemin GitLab :
 *   https://gitlab-entreprise.com/tribu-socle-xxxx/cats/p1234/s5678/fe01  ->  { produit: 'P1234', solution: 'S5678' }
 * Un segment « p » ou « s » suivi uniquement de chiffres (majuscule ou minuscule).
 */
function parseProjectCodes(url) {
  if (!url) return { produit: null, solution: null };
  const segs = String(url).replace(/\.git\/?$/, '').split(/[/:]/).filter(Boolean);
  const find = letter => { const s = segs.filter(x => new RegExp('^' + letter + '\\d+$', 'i').test(x)).pop(); return s ? s.toUpperCase() : null; };
  return { produit: find('p'), solution: find('s') };
}

/** Identifiant des rapports : P1234_S5678_fe01 (les codes absents sont omis). */
function reportBaseName({ produit, solution, projet }) {
  return [produit, solution, projet].filter(Boolean).join('_').replace(/[^\w.-]+/g, '_').slice(0, 120);
}

/**
 * Transforme une suite d'arguments en projets. Accepte des URL seules (nom déduit)
 * ou des paires « nom url », mélangées librement.
 */
function toProjects(tokens) {
  const out = [];
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (isUrl(t)) out.push({ name: nameFromUrl(t), url: t });
    else if (isUrl(tokens[i + 1])) { out.push({ name: t, url: tokens[i + 1] }); i++; }
    else throw new Error(`« ${t} » n'est pas une URL et n'est pas suivi d'une URL.`);
  }
  return out;
}

/** Découpe une ligne en arguments (gère les guillemets simples et doubles). */
function splitLine(line) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
  return out;
}

module.exports = { parseArgs, splitLine, OPTIONS_HELP, isUrl, nameFromUrl, toProjects, parseProjectCodes, reportBaseName };
