# Guide de développement — skill-analyse

Ce guide décrit le fonctionnement interne de l'outil et la manière de l'**adapter à vos propres projets** (frontends Angular, BFF Node.js, charts Helm de l'entreprise). Il s'adresse aux développeurs comme aux assistants IA (Copilot) chargés de faire évoluer l'outil.

Sommaire :
1. [Principes](#1-principes)
2. [Déroulement d'une analyse](#2-déroulement-dune-analyse)
3. [Les briques du code](#3-les-briques-du-code)
4. [Format d'un constat et d'une règle](#4-format-dun-constat-et-dune-règle)
5. [Les scanners](#5-les-scanners)
6. [Notation](#6-notation)
7. [Configuration](#7-configuration)
8. [Adapter l'outil à mes projets (calibrage)](#8-adapter-loutil-à-mes-projets-calibrage)
9. [Ajouter une règle](#9-ajouter-une-règle)
10. [Ajouter un scanner](#10-ajouter-un-scanner)
11. [Tests](#11-tests)
12. [Sécurité de l'outil lui-même](#12-sécurité-de-loutil-lui-même)
13. [Rapports](#13-rapports)
14. [Pièges connus](#14-pièges-connus)

---

## 1. Principes

| Principe | Conséquence pour le code |
|---|---|
| **Statique** | Le projet analysé n'est jamais exécuté. On lit des fichiers, on applique des expressions régulières, on lit l'historique git. |
| **Sans dépendance** | Uniquement les modules natifs de Node.js ≥ 18. Le poste cible n'a pas de droits administrateur et l'outil doit fonctionner sans `npm install`. |
| **Économe en tokens IA** | Les scripts font tout le travail. L'IA ne lit que `resume.md` (≈ 40 lignes) et `a-verifier.md` (extraits ciblés). Tout ce qui peut être décidé par un script doit l'être. |
| **Rapport toujours produit** | Un scanner qui échoue est marqué « erreur » ou « partiel », l'analyse continue. |
| **Hors ligne possible** | Tout contrôle réseau est optionnel, désactivable et bascule automatiquement en hors ligne. |
| **Configuration avant code** | Les spécificités d'un projet ou de l'entreprise passent par `config/`, `profils`, `allowlists/`, `rules/`. |
| **Français** | Tous les textes destinés à l'utilisateur sont en français. |

## 2. Déroulement d'une analyse

`lib/runner.js` → `runAudit(options)` :

1. **Configuration** : `config/settings.json` + `config/settings.local.json` (+ `--config`).
2. **Source** : clone sécurisé (`lib/clone.js`) dans `workspace/<nom>-<date>/`, ou dossier local (`--path`).
3. **Parcours** (`lib/fswalk.js`) : liste des fichiers ; `node_modules`, `.git`, `.angular`, `coverage`… ne sont pas lus (mais leur présence est signalée). Les liens symboliques ne sont jamais suivis. Lecture paresseuse avec cache (`ctx.readText(file)` → `null` si binaire ou trop gros).
4. **Type de projet** (`lib/detect.js`) : `Chart.yaml` → helm, `angular.json` / `@angular/core` → fe, sinon `package.json` → bff. Le nom n'est qu'un indice ; `--type` force le type.
5. **Environnement** (`lib/env.js`) : outils externes présents, accès réseau (OSV, registre, GitLab).
6. **Scanners** exécutés dans l'ordre de `SCANNERS` (voir §5). Chacun reçoit le même `ctx`.
7. **Post-traitement** : dédoublonnage → **profil** du type de projet (règles ramenées à Info) → **exclusions** (`allowlists/`) → tri → extraits de code pour les points à juger.
8. **Notation** (`lib/scoring.js`) et **comparaison** avec `reports/<identifiant>/derniere-analyse.json`. L'identifiant vaut `P1234_S5678_fe01` : codes produit et solution lus dans l'URL par `parseProjectCodes` (segments `p\d+` / `s\d+`, ou options `--produit` / `--solution`), puis nom du projet, assemblés par `reportBaseName` dans `lib/cli.js`. Le rapport complet s'appelle `<identifiant>_<horodatage>.md`. Les exclusions sont cherchées dans `allowlists/<identifiant>.json` puis `allowlists/<nom>.json`.
9. **Masquage global des secrets** (`lib/sanitize.js` → `maskDeep`) puis écriture des rapports (`lib/report.js`).
10. Suppression du clone (sauf `--keep`).

`audit-lot.js` appelle `runAudit` pour chaque projet puis écrit `reports/_lots/<date>/synthese.md`.

## 3. Les briques du code

| Fichier | Contenu |
|---|---|
| `lib/util.js` | `truncate`, `snippetAround`, `isInternalHost`, `extractUrls`, `hostOf`, `levenshtein`, `globToRegex`, `shannonEntropy`, `maskValue`, `daysAgo`, `parsePort` |
| `lib/finding.js` | `makeFinding(rule, data)`, `SEVERITIES`, `SEV_FR`, `CATEGORIES`, `sortFindings` |
| `lib/patterns.js` | `scanText(text, rules, opts)` et `scanLines(lines, rules, opts)` : applique des règles regex ligne par ligne, limite à `maxPerRule` occurrences (5 par défaut) et compte le reste dans `extra.occurrencesSupplementaires` |
| `lib/shell-rules.js` | `SHELL_RULES` (curl\|sh, reverse shell, base64 exécuté, LD_PRELOAD, persistance, TLS désactivé…) et `NET_RULES` (domaines suspects, IP publiques, métadonnées cloud, pilotage d'IA, C2 blockchain, mineurs, domaines IOC) |
| `lib/typosquat.js` | `typosquatTarget(nom)` à partir de `rules/paquets-populaires.json` |
| `lib/net.js` | `request`, `getJson`, `reachable` — proxy d'entreprise (`HTTPS_PROXY`, `NO_PROXY`), certificat (`NODE_EXTRA_CA_CERTS`), refus des redirections HTTPS→HTTP, `Authorization` retiré si changement d'hôte |
| `lib/tar.js` | `extractTgz(buffer)` : lecture en mémoire d'archives npm / charts Helm |
| `lib/git.js` | `git(args, cwd)` sécurisé : hooks neutralisés, `protocol.file` et `ext` interdits, sous-modules désactivés, LFS non téléchargé |
| `lib/clone.js` | `cloneRepo`, `repoInfo`, `parseGitlabUrl`, validation d'URL |
| `lib/cli.js` | Analyse des options communes à `audit.js` et `audit-lot.js` ; identifiant `P1234_S5678_projet` |
| `lib/diagnostic.js` | `node audit.js --diagnostic [url]` : vérification du poste (Node, git, configuration, proxy/certificat, registre, OSV, GitLab, token et ses droits, accès au projet et rôle). Toute nouvelle dépendance à l'environnement doit y être ajoutée. |
| `lib/sanitize.js` | `maskDeep`, `maskString`, `sanitizeUrl`, `sanitizeText` |
| `lib/allowlist.js` | Chargement et application des exclusions |
| `lib/scoring.js` | `computeScore`, `failsThreshold` |
| `lib/report.js` | `writeReports`, `writeBatchReport` |

## 4. Format d'un constat et d'une règle

### Règle

```js
{
  id: 'DOCKER_ADD_URL',          // MAJUSCULES, préfixe = domaine (DOCKER_, CODE_, SRV_, K8S_, PKG_, DEP_, GIT_, GITLAB_, IDE_, IA_, UNICODE_, NET_, SH_, SECRET_, STRUCT_)
  sev: 'high',                   // critical | high | medium | low | info
  cat: 'docker',                 // clé de CATEGORIES (lib/finding.js)
  title: 'ADD depuis une URL distante',
  desc: 'Pourquoi c\'est un risque (une ou deux phrases).',
  fix: 'Comment corriger.',
  review: true,                  // nécessite un jugement humain/IA → apparaît dans a-verifier.md
  // Pour les règles regex (lib/patterns.js) :
  re: /.../,                     // SANS drapeau g
  exclude: /.../,                // facultatif : ligne ignorée si elle correspond
  filter: (line, match, opts) => true | false | { severity, evidence, description }, // facultatif
  sevByType: { fe: 'critical' }, // facultatif : sévérité selon le type de projet
  mask: true,                    // facultatif : masque la valeur trouvée dans l'extrait
}
```

### Constat (produit par `makeFinding`)

```js
{
  rule, title, severity, category,
  file, line, evidence,          // emplacement et extrait (300 caractères max)
  description, recommendation,
  needsReview, source,           // source : 'interne' ou nom de l'outil externe
  extra,                         // facultatif : occurrencesSupplementaires, commits, exemples…
  fingerprint,                   // empreinte (règle + fichier + extrait) pour comparer deux analyses
}
```

### Catégories (`lib/finding.js` → `CATEGORIES`)

`dependances`, `package`, `docker`, `code`, `ide`, `serveur`, `k8s`, `shell`, `secrets`, `structure`, `git`, `gitlab`, `outils`. L'ordre d'affichage est `CAT_ORDER` dans `lib/report.js`.

## 5. Les scanners

Chaque scanner est un module :

```js
module.exports = {
  id: 'dockerfile',
  label: 'Dockerfile',                     // affiché dans le rapport
  category: 'docker',
  controls: ['Liste des contrôles…'],     // affichés dans « Contrôles effectués »
  async run(ctx) {
    return {
      findings: [],                        // constats
      filesAnalyzed: 0,
      status: 'ok',                        // ok | partiel | non exécuté | non applicable | erreur
      notes: [],                           // remarques affichées dans le rapport
      inventory: {},                       // fusionné dans res.inventaire (tableaux concaténés)
    };
  },
};
```

### Le contexte `ctx`

| Champ | Contenu |
|---|---|
| `root` | Dossier analysé |
| `files` | `[{ rel, abs, base, ext, size, tooLarge }]` (chemins `rel` avec `/`) |
| `readText(file)` | Contenu texte ou `null` (binaire / trop gros) |
| `skippedDirs`, `symlinks` | Dossiers non lus, liens symboliques trouvés |
| `config` | Configuration fusionnée |
| `options` | Options de ligne de commande (`days`, `noApi`, `ref`…) |
| `projectType` | `fe`, `bff`, `helm` ou `inconnu` |
| `profil` | `config.profils[projectType]` |
| `repo` | `{ isRepo, commit, branch, defaultBranch, shallow }` |
| `previous` | Résultat de l'analyse précédente (ou `null`) |
| `tools` | Chemins des outils externes trouvés (`ctx.tools.helm`…) |
| `network`, `offline` | Accès réseau disponibles, mode hors ligne |
| `gitlab`, `gitlabHost` | `{ host, projectPath }` extraits de l'URL |
| `gitCandidates` | Commits directs probables trouvés par `git-local` (utilisés par `gitlab-api`) |

### Liste et ordre

| Scanner | Fichier | Contrôle |
|---|---|---|
| Structure | `structure.js` | node_modules/dist versionnés, binaires, archives, fausses images/polices, fichiers hors de leur place, fichiers IOC, sous-modules |
| Secrets | `secrets.js` | Tokens, clés, fichiers sensibles (`RULES` exportées et réutilisées par `git-local`) |
| Dockerfile | `dockerfile.js` | Instructions, image, USER, EXPOSE, `.dockerignore` + `SHELL_RULES` |
| Scripts shell | `shell-scripts.js` | `.sh/.ps1/.bat`, Makefile, hooks git (husky) |
| Code source | `source-code.js` | Règles `RULES` (+ `MINIFIED_RULES` à fort signal), Unicode bidi, entropie, corrélations exfiltration/keylogger, angular.json, CSP, ports d'écoute, inventaire des domaines |
| Unicode | `unicode.js` | Sélecteurs de variante (GlassWorm), caractères tags, bidi/largeur nulle hors code |
| IDE et IA | `ide-ai.js` | `.vscode/tasks.json` (folderOpen), settings, devcontainer, IntelliJ, MCP, hooks d'assistants, fichiers d'instructions IA |
| Config serveur | `server-config.js` | nginx / apache / supervisord (fonctions `analyzeNginx`, `analyzeApache` réutilisées par `k8s-helm`) |
| package.json | `package-json.js` | Scripts de cycle de vie, sources de dépendances, typosquatting, `.npmrc`, `.yarnrc`, `.pnpmfile` |
| Dépendances | `dependencies.js` | Lockfile (scripts d'installation, sources, intégrité, cohérence, IOC) ; en ligne : archives, OSV, dates, éditeur, provenance, manifest confusion |
| Helm/K8s/CI | `k8s-helm.js` | Règles `RULES` ligne par ligne, blocs YAML multi-lignes (ConfigMaps), Chart.yaml, sous-charts `.tgz`, `.gitlab-ci.yml`, `helm template` |
| Git local | `git-local.js` | Tags non fusionnés, refs comparées à l'analyse précédente, commits directs, dates, emails, lignes ajoutées récemment |
| API GitLab | `gitlab-api.js` | Protections, approbations, MR, commits sans MR, événements, plateforme (webhooks, miroirs, clés, tokens, variables) |
| Outils externes | `external-tools.js` | gitleaks, trivy, osv-scanner, hadolint, kube-linter s'ils sont présents |

## 6. Notation

`lib/scoring.js` :
- Pénalité par règle : critique 30, élevé 12, moyen 4, faible 1, info 0 ; chaque occurrence supplémentaire de la même règle ajoute 50 %, plafonné à x3.
- Score = 100 − pénalités (minimum 0). Note : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E < 40.
- Plafonds : ≥ 1 règle critique → D au mieux ; ≥ 3 règles critiques → E ; ≥ 3 règles élevées → C au mieux.
- Une note par catégorie est aussi calculée.

Pour rendre une règle **informative sans impact sur la note**, utiliser `profils.<type>.reglesInformatives` plutôt que de changer sa sévérité dans le code.

## 7. Configuration

`config/settings.json` (valeurs par défaut, versionné) est surchargé par `config/settings.local.json` (poste cible, non versionné). Clés principales :

| Clé | Usage |
|---|---|
| `gitlab.url`, `gitlab.tokenEnv` | Instance GitLab, variable du token |
| `npm.artifactoryUrl`, `npm.registresAutorises`, `npm.scopesInternes`, `npm.paquetsInternesNonScopes` | Registres autorisés, paquets internes |
| `docker.registresAutorises`, `helm.depotsAutorises` | Sources d'images et de charts autorisées |
| `domaines.internes`, `domaines.emailsDeveloppeurs` | Hôtes considérés internes, domaines email des auteurs |
| `git.branchesProtegees`, `git.formatTag`, `git.periodeJours`, `git.tagsMinimum`, `git.maxCommits` | Analyse git |
| `ports.attendus` | Ports considérés normaux |
| `enLigne.*` | Activation et limites des contrôles réseau |
| `notation.seuilEchecCI` | Note qui fait échouer `--ci` |
| `analyse.tailleMaxFichierKo`, `analyse.extraitsAVerifier` | Taille max lue, nombre d'extraits pour l'IA |
| `profils.<fe\|bff\|helm>` | `reglesInformatives`, `verifierCommitsSansMR` |

Autres données ajustables sans code :
- `rules/paquets-populaires.json` : un paquet présent n'est jamais signalé comme typosquatting ;
- `rules/ioc.json` : versions compromises, noms de fichiers, domaines d'attaque ;
- `scanners/dependencies.js` → `KNOWN_INSTALL` : paquets dont le script d'installation est connu et légitime ;
- `allowlists/<projet>.json` : exclusions justifiées par projet.

## 8. Adapter l'outil à mes projets (calibrage)

Objectif : que l'outil signale **tout ce qui est réellement suspect** dans vos projets, et **rien d'autre**. Procédure à suivre (c'est ce que fait le prompt `/calibrer-sur-mes-projets`) :

### Étape 1 — Analyser un projet de référence

```powershell
node audit.js fe01 <url> --keep --no-save
```
`--keep` conserve le clone dans `workspace/` pour pouvoir vérifier les constats.

### Étape 2 — Classer chaque constat

| Cas | Action |
|---|---|
| **Vrai problème** | Rien à changer dans l'outil (corriger le projet). |
| **Faux positif propre à l'entreprise** (domaine interne, registre, port, nom de branche, image de base…) | Compléter `config/settings.local.json` (`domaines.internes`, `ports.attendus`, `docker.registresAutorises`, `npm.scopesInternes`, `git.branchesProtegees`…). |
| **Faux positif propre à un projet** (ex. un `bypassSecurityTrustHtml` relu et justifié) | Ajouter une exclusion dans `allowlists/<projet>.json` avec justification et date d'expiration. |
| **Règle trop bruyante pour un type de projet** | L'ajouter à `profils.<type>.reglesInformatives`. |
| **Faux positif dû à la règle elle-même** (motif trop large) | Affiner la regex (`exclude`, `filter`) **et** ajouter un cas négatif dans les tests (le projet propre doit rester propre). |
| **Paquet légitime signalé** (typosquatting, script d'installation) | Ajouter à `rules/paquets-populaires.json` ou à `KNOWN_INSTALL`. |

### Étape 3 — Chercher les oublis (faux négatifs)

Lister ce qui est spécifique à vos projets et que l'outil ne vérifie pas encore. Exemples d'adaptations utiles :
- **Conventions d'architecture** : fichiers de configuration nginx attendus à un emplacement précis, structure de chart Helm standard de l'entreprise (signaler tout fichier en dehors) ;
- **Bibliothèques internes** : scope npm interne, versions minimales imposées, bibliothèques interdites ;
- **Images de base imposées** : liste blanche stricte d'images Docker (`docker.registresAutorises` ou nouvelle règle sur le nom exact) ;
- **Variables d'environnement attendues** dans les charts, endpoints internes autorisés ;
- **Mécanismes d'authentification** propres (ex. intercepteur HTTP Angular officiel → exclure ce fichier de `CODE_DETOURNEMENT_GLOBAL`).

Chaque oubli devient une règle (voir §9) avec un cas de test.

### Étape 4 — Valider

```powershell
npm test
node audit-lot.js --fichier mes-projets.txt --no-save
```
Comparer les notes avant/après ; vérifier que les projets sains sont notés A ou B.

## 9. Ajouter une règle

### Règle regex simple (le cas le plus fréquent)

1. Choisir le bon endroit :
   - motif de **commande shell** (Dockerfile, scripts, YAML, scripts npm) → `SHELL_RULES` dans `lib/shell-rules.js` ;
   - motif **réseau** valable partout (code + shell + YAML) → `NET_RULES` ;
   - motif de **code JavaScript/TypeScript** → `RULES` dans `scanners/source-code.js` (et dans `MINIFIED_RULE_IDS` si le signal est fort, pour qu'il s'applique aussi aux fichiers minifiés, aux archives npm inspectées et à l'historique git) ;
   - motif **Kubernetes/Helm** → `RULES` dans `scanners/k8s-helm.js` ;
   - **secret** → `RULES` dans `scanners/secrets.js` (avec `mask: true`).
2. Écrire la règle (format §4) : `id` unique, `title` / `desc` / `fix` en français, regex sans `g`.
3. Ajouter un cas positif dans `tests/fixtures.js` (motif découpé avec `J(...)`) et l'`id` dans la liste `rules` du projet concerné dans `tests/run-tests.js`.
4. Si risque de faux positif, ajouter un cas négatif dans le projet propre (`feClean`).
5. `npm test`.

### Règle structurelle (logique au-delà d'une ligne)

L'écrire dans la fonction `run` du scanner concerné : définir la règle dans l'objet `R` du fichier, puis `findings.push(makeFinding(R.MA_REGLE, { file, line, evidence }))`.

### Règle en ligne (réseau)

Uniquement dans `scanners/dependencies.js` ou `scanners/gitlab-api.js`, toujours :
- conditionnée par `!ctx.offline` et `ctx.network.<service>` ;
- via `lib/net.js` ;
- sans jamais envoyer de nom de paquet interne à un service public (`isInternal()`), ni de code ;
- limitée en nombre de requêtes (`enLigne.maxRequetes`).

## 10. Ajouter un scanner

1. Créer `scanners/mon-scanner.js` avec l'interface §5.
2. L'ajouter à `SCANNERS` dans `lib/runner.js` (l'ordre compte si un scanner dépend d'un autre, comme `gitlab-api` après `git-local`).
3. Si nouvelle catégorie : l'ajouter à `CATEGORIES` (`lib/finding.js`) et à `CAT_ORDER` (`lib/report.js`).
4. Ajouter fixtures + attentes dans les tests.
5. Mettre à jour le tableau « Contrôles effectués » du `README.md` et ce guide.

## 11. Tests

```powershell
npm test               # les trois suites
KEEP=1 npm test        # conserve les projets générés dans tests/.tmp pour inspection
VERBOSE=1 node tests/run-tests.js   # affiche le chemin des rapports générés
```

| Suite | Contenu |
|---|---|
| `tests/fixtures.js` | Génère à la volée : `fe01` (frontend piégé), `bff01`, `helm01`, `fe-propre` (doit rester A/B), un dépôt git (tag non fusionné, push direct, date future, auteur externe) |
| `tests/run-tests.js` | Vérifie que chaque règle attendue se déclenche, le type détecté, la note du projet propre, le profil helm, le mode lot |
| `tests/securite.js` | Aucune connexion en hors ligne (http/https/net interceptés), aucun secret dans les rapports, tokens jamais envoyés à un mauvais hôte, URL du lockfile jamais suivie hors registres |
| `tests/gitlab-mock.js` | Scanner GitLab contre une API simulée (21 contrôles), valeurs des variables CI jamais conservées |

Les fixtures sont **générées**, jamais versionnées, et supprimées à la fin (sauf `KEEP=1`) : elles ressemblent volontairement à des malwares et déclencheraient les antivirus et la protection anti-secrets de GitLab.

## 12. Sécurité de l'outil lui-même

L'outil manipule du code potentiellement hostile. À préserver lors de toute évolution :
- **Clone** : `lib/git.js` (hooks neutralisés, pas de sous-modules, pas de LFS, `protocol.file` interdit) ; URL validée (`https`, `ssh`, `git@`).
- **Aucune exécution** du projet ; `execFileSync` sans shell ; arguments git toujours sous forme de refs complètes (`refs/...`) ou de SHA.
- **Réseau** : seulement `lib/net.js` ; l'URL `resolved` d'un lockfile n'est jamais appelée hors registres autorisés (`tarballUrl`) ; tokens envoyés uniquement en HTTPS à l'hôte exact (`authHeaders`, contrôle d'hôte dans `gitlab-api`).
- **Sorties** : `maskDeep` sur tout le résultat ; identifiants retirés des URL (`sanitizeUrl`) et des messages d'erreur (`sanitizeText`).
- **Injection de consignes** : `resume.md` et `a-verifier.md` commencent par un avertissement « données non fiables » ; les extraits sont dans des blocs de code neutralisés.
- **Archives** : décompression en mémoire avec limites (`lib/tar.js`), jamais écrites sur disque.

## 13. Rapports

| Fichier | Lecteur | Contenu |
|---|---|---|
| `resume.md` | IA | Note, compteurs, 15 principaux constats, contrôles partiels, chemins |
| `a-verifier.md` | IA | Constats `needsReview` avec extrait ± 4 lignes et consigne de verdict |
| `<identifiant>_<horodatage>.md` | Humain | Rapport complet : codes produit / solution, synthèse, notes par catégorie, évolution, contrôles effectués, détail par règle (pourquoi / recommandation / occurrences), inventaire, exclusions, méthode |
| `resultats.json` | Machine | Tout le résultat (sert aussi de référence `derniere-analyse.json`) |
| `_lots/<date>/synthese.md` | IA / humain | Tableau de bord multi-projets |

Pour modifier la présentation : `renderFull`, `renderSummary`, `renderReview`, `renderBatch` dans `lib/report.js`. Garder `resume.md` **court** (c'est lui qui coûte des tokens à chaque analyse).

## 14. Pièges connus

- **Regex avec drapeau `g`** dans une règle : résultats aléatoires (`lastIndex`). Interdit.
- **Modifier un fichier par commande shell** (sed, node -e) : les apostrophes françaises et les `\` des regex sont souvent corrompus. Utiliser un éditeur.
- **`apache` vs `nginx`** : la détection est sensible à la casse (`Listen` Apache vs `listen` nginx).
- **Lockfile v1** : pas de `hasInstallScript` ; les scripts d'installation ne sont détectés qu'en ligne.
- **Profil helm** : les règles de merge/commit direct y sont informatives par choix ; ne pas « corriger » ce comportement sans demande.
- **`DEP_CHANGEMENT_EDITEUR`** : limité aux versions de moins de 180 jours et aux comptes jamais vus sur le paquet, sinon trop bruyant (projets à plusieurs mainteneurs).
- **Faux positifs dans les fichiers de test** des projets analysés : `secrets.js` abaisse la sévérité des secrets génériques et JWT dans les `*.spec.ts`, `tests/`, `fixtures/`.
- **Windows** : chemins internes toujours en `/` (`file.rel`) ; ne pas comparer avec des chemins `\`.
