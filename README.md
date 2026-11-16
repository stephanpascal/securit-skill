# skill-analyse — Audit de sécurité de projets fe / bff / Helm

Outil d'audit **statique** qui recherche backdoors, code malveillant, scripts exécutés à l'installation npm, configurations serveur détournées et comportements git suspects dans trois types de projets :

| Type | Exemples de noms | Détection automatique |
|---|---|---|
| Frontend Angular | `fe`, `fe01`, `frontend` | `angular.json` ou `@angular/core` |
| BFF Node.js | `bff`, `bff01`, `back-for-front` | `package.json` sans framework frontend |
| Déploiement Helm | `helm-…`, `deploy-…` | `Chart.yaml` |

Les scripts font tout le travail et produisent un rapport Markdown détaillé avec une **note de A à E**. L'IA (Copilot ou Claude) se contente de lancer une commande, de lire un **résumé court** et de juger les quelques **points ambigus** : consommation de tokens minimale.

> **Sécurité** : aucune commande du projet analysé n'est exécutée (jamais de `npm install`). Le clone est sécurisé (hooks neutralisés, pas de sous-modules, pas de LFS, protocoles `file://` et `ext::` interdits, liens symboliques non suivis) et supprimé après l'analyse. Les secrets détectés sont masqués dans les rapports.

---

## Prérequis

- **Node.js ≥ 18** et **git** (aucune dépendance npm, aucun droit administrateur).
- Accès au dépôt GitLab (clé SSH ou identifiants HTTPS déjà configurés).
- Optionnel : variable `GITLAB_TOKEN` (droit `read_api`) pour les contrôles merge requests / approbations / protections.
- Optionnel : outils externes (`tools/setup-tools.ps1`).

## Installation sur le poste cible

```powershell
git clone <url-de-ce-depot> D:\outils\skill-analyse
cd D:\outils\skill-analyse
powershell -ExecutionPolicy Bypass -File integration\install.ps1          # skill + prompt Copilot
powershell -ExecutionPolicy Bypass -File integration\install.ps1 -Claude  # + skill Claude Code
powershell -ExecutionPolicy Bypass -File tools\setup-tools.ps1            # optionnel : outils externes
```

`install.ps1` copie le skill dans `~/.copilot/skills/security-audit/`, le prompt dans le profil VS Code, et crée `config/settings.local.json` à compléter.

### Vérifier que le poste est prêt

```powershell
node audit.js --diagnostic https://gitlab-entreprise.com/tribu-socle-xxxx/cats/p1234/s5678/fe01
```

En quelques secondes, avec ✅ / ⚠️ / ❌ et la solution pour chaque problème :
- logiciels : Node.js, git, outils optionnels ;
- configuration : Artifactory, scopes internes, domaines, dossiers accessibles en écriture ;
- réseau : proxy, certificat d'entreprise, registre npm, OSV, API GitLab ;
- token GitLab : présence, validité, droits ;
- projet : identifiant lu dans l'URL, accès git, rôle sur le projet (Maintainer requis pour les contrôles de plateforme).

Aucun secret n'est affiché. Ajouter `--offline` pour ne pas tester le réseau.

### Configuration (`config/settings.local.json`)

| Clé | Rôle |
|---|---|
| `npm.artifactoryUrl` | URL du dépôt npm Artifactory (ex. `https://artifactory.xxx/artifactory/api/npm/npm-virtual/`). Utilisée pour les requêtes et ajoutée aux registres autorisés. |
| `npm.registresAutorises` | Registres acceptés dans le lockfile et le `.npmrc`. |
| `npm.scopesInternes` | Scopes internes (`@entreprise`) : détection de confusion de dépendances. |
| `npm.paquetsInternesNonScopes` | Paquets internes sans scope : vérifie qu'ils n'existent pas sur npmjs. |
| `docker.registresAutorises` | Registres d'images autorisés (Dockerfile et manifestes). |
| `helm.depotsAutorises` | Dépôts de charts autorisés. |
| `gitlab.api` | `"auto"` (défaut) : API utilisée si un token est présent ; `false` : **analyse par clone local uniquement**, aucun appel à l'API, aucun avertissement de token. |
| `gitlab.url` | URL de l'instance GitLab (sinon déduite de l'URL du projet). |
| `domaines.internes` | Domaines considérés comme internes (proxy, URL du code). |
| `domaines.emailsDeveloppeurs` | Domaines email attendus des auteurs de commits (ex. `entreprise.fr`). |
| `git.branchesProtegees` | `main`, `master`, `develop` (motifs `release/*` acceptés). |
| `git.formatTag` | Expression régulière des tags (défaut `x.y.z` / `x.y.z-a`). |
| `git.periodeJours` | Période d'historique analysée (défaut 30 jours, option `--days`). |
| `ports.attendus` | Ports considérés comme normaux. |
| `notation.seuilEchecCI` | Note à partir de laquelle `--ci` renvoie le code 2 (défaut `D`). |

Variables d'environnement : `GITLAB_TOKEN`, `NPM_TOKEN` (Artifactory si authentifié), `HTTPS_PROXY`, `NO_PROXY`, `NODE_EXTRA_CA_CERTS` (certificat d'entreprise).

## Utilisation

### Depuis Copilot Chat (mode Agent)

```
/security-audit https://gitlab.entreprise.fr/equipe/fe01.git
/security-audit https://gitlab.entreprise.fr/equipe/fe01.git https://gitlab.entreprise.fr/equipe/bff01.git https://gitlab.entreprise.fr/equipe/helm01.git
/security-audit git@gitlab.entreprise.fr:equipe/bff01.git --ref 2.3.1
```

Le nom de chaque rapport est déduit de l'URL (`…/equipe/fe01.git` → `fe01`). Pour choisir un autre nom, le placer avant l'URL : `/security-audit front-principal https://…/fe01.git`.

### En ligne de commande

```powershell
node audit.js https://gitlab.entreprise.fr/equipe/fe01.git
node audit.js https://gitlab.entreprise.fr/equipe/helm01.git --ref 1.4.0 --days 90
node audit.js bff01 --path D:\dev\bff01                 # dossier déjà présent
node audit.js bff01 https://…/bff01.git --path D:\dev\bff01   # dossier local + contrôles API GitLab
```

| Option | Effet |
|---|---|
| `--type fe\|bff\|helm` | Forcer le type |
| `--ref <branche\|tag>` | Analyser une branche ou un tag précis (ex. la version en production) |
| `--days <n>` | Période d'historique git |
| `--shallow` | Clone superficiel (rapide, sans analyse git) |
| `--offline` | Aucun accès réseau |
| `--no-api` | Pas d'appel à l'API GitLab |
| `--keep` | Conserver le clone dans `workspace/` |
| `--out <dossier>` | Dossier des rapports |
| `--ci` | Code de sortie 2 si la note atteint le seuil |
| `--no-save` | Ne pas servir de référence pour la prochaine comparaison |

### Plusieurs projets en une commande

```powershell
# liste d'URL (les options s'appliquent à tous ; les noms sont déduits des URL)
node audit-lot.js https://…/fe01.git https://…/bff01.git https://…/helm01.git --days 60

# ou fichier de projets (voir projets.exemple.txt), chaque ligne pouvant avoir ses propres options
node audit-lot.js --fichier projets.txt
```

```text
# projets.txt — une URL par ligne
https://gitlab.entreprise.fr/equipe/fe01.git
https://gitlab.entreprise.fr/equipe/bff01.git    --ref 2.3.1
https://gitlab.entreprise.fr/equipe/helm01.git
```

Dans Copilot : `/security-audit <url1> <url2> <url3>` ou `/security-audit --fichier D:\listes\projets.txt`.

Les projets sont analysés à la suite ; une erreur (dépôt inaccessible…) n'interrompt pas le lot. Chaque projet garde ses rapports habituels, et une **synthèse** est produite dans `reports/_lots/<date>/synthese.md` (+ `synthese.json`) : tableau de bord trié du plus au moins risqué, évolution depuis l'analyse précédente, projets à examiner en priorité (D/E) et projets en erreur. Avec `--ci`, le code de sortie vaut 2 si un projet atteint le seuil ou échoue. Copilot ne lit que la synthèse, puis les résumés des projets notés D ou E.

### Profils par type de projet

La section `profils` de la configuration ajuste l'analyse par type (`fe`, `bff`, `helm`) :

- `reglesInformatives` : constats conservés dans le rapport mais ramenés à **Info** (hors note) et regroupés en un seul constat par règle, avec des exemples ;
- `verifierCommitsSansMR: false` : pas de vérification API commit par commit.

**Par défaut, pour les dépôts Helm** (mises à jour fréquentes et désordonnées), les merges et commits directs ne sont pas surveillés finement : commits poussés directement, merges hors GitLab, MR sans approbation ou fusionnées par leur auteur, règles d'approbation, messages anodins, nouveaux auteurs, format des tags. **Restent actifs** : tags déplacés ou supprimés, historique réécrit et push forcé, tags non fusionnés modifiant des fichiers sensibles, code dangereux et secrets introduits dans l'historique, emails externes, dates futures, et bien sûr toute l'analyse du contenu (Helm, ConfigMaps, nginx…). Le profil appliqué est indiqué dans la synthèse du rapport.

## Rapports produits

Le **code produit** (`pXXXX`) et le **code solution** (`sXXXX`) sont lus dans l'URL GitLab, par exemple `https://gitlab-entreprise.com/tribu-socle-xxxx/cats/p1234/s5678/fe01`. Ils sont mis en majuscules et forment l'identifiant du projet `P1234_S5678_fe01`. Les codes absents de l'URL sont omis ; pour un dossier local, utilisez `--produit` et `--solution`.

```text
reports\
  P1234_S5678_fe01\                              ← historique du projet
    derniere-analyse.json                        ← référence de comparaison
    P1234_S5678_fe01_2026-11-16_215611\          ← une analyse
      P1234_S5678_fe01_2026-11-16_215611.md      ← rapport complet
      resume.md   a-verifier.md   resultats.json
  _lots\
    synthese_2026-11-16_220000\synthese_2026-11-16_220000.md   ← synthèse multi-projets
```

| Fichier | Contenu | Lecteur |
|---|---|---|
| `resume.md` | Note, top 15 des constats, contrôles partiels (≈ 40 lignes) | IA |
| `a-verifier.md` | Points ambigus avec extrait de code (± 4 lignes) et consigne de verdict | IA |
| `<identifiant>_<horodatage>.md` | Rapport complet (codes produit / solution en tête) : synthèse, notes par catégorie, évolution, contrôles effectués, détail de chaque constat (pourquoi / recommandation / occurrences), inventaire (domaines, ports, images, scripts npm, dépendances à script d'installation, tags, commits directs, MR) | Humain |
| `resultats.json` | Données complètes | Machine / CI |

`reports/<identifiant>/derniere-analyse.json` sert de référence : l'analyse suivante signale les **nouveaux constats**, l'évolution de la note, les **tags déplacés** et l'**historique réécrit**.

## Notation

- Score sur 100 : chaque règle déclenchée retire des points (critique 30, élevé 12, moyen 4, faible 1), les répétitions d'une même règle comptent de moins en moins (x3 maximum).
- Note : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E < 40.
- **Plafonds** : un seul constat critique → D au mieux ; 3 règles critiques → E ; 3 règles élevées → C au mieux. Une vraie backdoor ne peut donc jamais être « noyée » dans une bonne note.

## Contrôles effectués

| Analyse | Principaux contrôles |
|---|---|
| **Dépendances** | Lecture statique de `package-lock.json` : dépendances transitives à script d'installation (`hasInstallScript`), sources hors Artifactory, git/URL, intégrité, typosquatting, confusion de dépendances. En ligne : téléchargement des archives à script d'installation **sans exécution** (vérification d'empreinte, analyse du script et du fichier JS appelé), vulnérabilités et **paquets malveillants connus** (OSV.dev / OpenSSF), versions publiées très récemment, paquets introuvables (slopsquatting), **éditeur inconnu** sur une version récente, **perte d'attestation de provenance**, scripts différents entre registre et archive (manifest confusion). Hors ligne : **versions compromises connues** (`rules/ioc.json` : Shai-Hulud, chalk/debug, Nx s1ngularity…), **lockfile falsifié** (archive d'un autre paquet), dépendances en HTTP non chiffré. |
| **package.json / npm** | `preinstall` / `install` / `postinstall` / `prepare`, motifs dangereux dans tous les scripts, dépendances git/URL/fichier, versions `*`/`latest`, typosquatting, `overrides`, `.npmrc` (registre, `script-shell`, `node-options`, `strict-ssl`), `.yarnrc.yml` (`yarnPath`), `.pnpmfile.cjs`, lockfile absent. |
| **Dockerfile** | `curl \| sh`, reverse shell, base64 exécuté, `ADD` d'URL, image non figée ou de registre non autorisé, secrets dans `ENV`/`ARG`, `NODE_OPTIONS --require`, `npm install` sans `--ignore-scripts`, root, ports inhabituels / SSH, script de démarrage absent du dépôt, `COPY --from` image externe, `.dockerignore` absent ou incomplet. |
| **Code source** | `eval`, `new Function`, `vm`, `child_process` (critique dans un front), exécution d'une entrée HTTP, obfuscation (`_0x…`, hex, `fromCharCode`, base64, entropie, lignes très longues), caractères invisibles / bidirectionnels (Trojan Source) / homoglyphes, exfiltration (cookies, `process.env`, fichiers d'identifiants + envoi externe), keyloggers, skimmers, détournement de `fetch`/XHR, injection de scripts, `bypassSecurityTrust*`, scripts globaux d'`angular.json`, scripts externes dans `index.html`, serveurs réseau cachés, ports d'écoute, routes suspectes, CORS, TLS désactivé, domaines suspects, IP publiques, mineurs. **Attaques 2025-2026** : pilotage d'assistants IA sans garde-fou (`claude --dangerously-skip-permissions`, `gemini --yolo`… — s1ngularity), comportements de ver (`npm publish`, API GitHub en écriture, trufflehog — Shai-Hulud), serveur de commande caché dans une blockchain (EtherHiding), domaines IOC. Angular : source maps en production, CSP absente, service worker vers des ressources externes. |
| **IDE et assistants IA** | Tâches VS Code lancées **à l'ouverture du dossier** (`runOn: folderOpen` — Contagious Interview), faux fichiers lancés avec Node (fausses polices `.woff2`), paramètres versionnés activant les tâches automatiques / désactivant la confiance / auto-approuvant les outils de l'IA / remplaçant des exécutables, devcontainer (`initializeCommand` exécutée sur le poste), configurations IntelliJ, **serveurs MCP** (téléchargés à la volée), hooks d'assistants, **fichiers d'instructions IA** (`copilot-instructions.md`, `AGENTS.md`, `CLAUDE.md`, `.cursorrules`…) et consignes d'injection. |
| **Unicode (tous fichiers)** | Suites de sélecteurs de variante invisibles encodant une charge (**GlassWorm**), caractères « tags » invisibles (texte caché décodé dans le rapport), bidi et largeur nulle dans les fichiers non-code. |
| **Configurations serveur** | nginx / apache / `.htaccess` / supervisord : ports, proxy vers l'extérieur ou ouvert (`$arg_…`), lua / perl / njs, `mirror`, `sub_filter`, journaux externes ou vers une commande, CGI, PHP sur extensions d'images, `auto_prepend_file`, alias traversal, listing, en-têtes de sécurité, TLS obsolète. |
| **Helm / Kubernetes / CI** | Hooks Helm, `postStart`, `initContainers`, `sh -c`, privileged, host*, `hostPath` (docker.sock…), capacités, RBAC `*` / cluster-admin / secrets, webhooks, DaemonSet, CronJob, NodePort/LoadBalancer, snippets Ingress, `hostAliases`, proxy, `lookup`, Secrets versionnés, configurations nginx/apache/JS **embarquées dans les ConfigMaps**, sous-charts `.tgz` décompressés, dépôts de charts, rendu `helm template` (si helm présent), `.gitlab-ci.yml` (inclusions distantes, push/tag, tokens envoyés). |
| **Scripts shell** | `.sh`, `.ps1`, `.bat`, Makefile, shebang, **hooks git versionnés** (husky…) exécutés sur les postes développeurs. |
| **Secrets** | Clés privées, tokens GitLab/GitHub/npm/Artifactory, AWS/Azure/Google/Stripe/Slack, JWT, identifiants dans les URL, fichiers sensibles versionnés. |
| **Structure** | `node_modules`/`dist` versionnés, binaires, archives, scripts dans `src/`/`assets/`, doubles extensions, fausses images et fausses polices, fichiers portant un nom d'IOC (`shai-hulud`…), **fichiers hors de leur place** (manifeste k8s ou config serveur dans un fe/bff, code dans un chart), liens symboliques, sous-modules. |
| **Historique git** | **Tags absents de toutes les branches protégées** (code livré sans merge) avec diff et auteurs, tags hors format, tags déplacés / supprimés, historique réécrit (push forcé), commits poussés directement, merges hors GitLab, dates futures / antidatées, emails externes, nouveaux auteurs sur fichiers sensibles, messages anodins masquant des modifications sensibles, `.gitignore` + build et binaires dans les tests (schéma **xz-utils**), motifs dangereux et secrets dans les commits récents de toutes les branches. |
| **API GitLab** | Branches non protégées, push direct / forcé autorisé, tags non protégés, règles d'approbation (selon l'édition), **MR fusionnées sans approbation**, **auto-merge** par l'auteur, auto-approbation, **commits sans MR (push direct confirmé)**, événements de push sur branches protégées, push forcé probable, création/suppression de tags, projet public. **Plateforme** (rôle Maintainer) : **webhooks vers l'extérieur**, **miroirs distants**, clés de déploiement en écriture, tokens de projet sans expiration, variables CI sensibles non masquées / non protégées (valeurs jamais conservées). |
| **Outils externes** | gitleaks, trivy, osv-scanner, hadolint, kube-linter s'ils sont présents. |

## Confidentialité et flux réseau

Aucune télémétrie. Toutes les connexions passent par `lib/net.js` ; les processus lancés (git, helm, outils optionnels) le sont sans shell. En mode `--offline`, **aucune** connexion n'est émise (vérifié par `tests/securite.js`).

| Destination | Ce qui est envoyé | Désactivation |
|---|---|---|
| Instance GitLab (clone + API) | Requêtes de lecture du projet ; token `GITLAB_TOKEN` envoyé **uniquement en HTTPS à l'hôte du projet**, et refusé s'il diffère de `gitlab.url` | `--no-api`, `--offline` |
| Artifactory (ou registry.npmjs.org si non configuré) | Noms et versions des dépendances directes et à script d'installation ; téléchargement de leurs archives. Token `NPM_TOKEN` **uniquement en HTTPS vers l'hôte Artifactory**. Les URL `resolved` du lockfile ne sont jamais appelées si elles sortent des registres autorisés. Paquets internes jamais demandés au registre public. | `enLigne.inspecterArchives`, `enLigne.datesPublication`, `--offline` |
| api.osv.dev | Noms et versions des paquets **publics** du lockfile (jamais les paquets internes, jamais de code) | `enLigne.osv: false`, `--offline` |
| registry.npmjs.org (option) | Noms de `npm.paquetsInternesNonScopes`, seulement si `enLigne.verifierNomsInternesSurNpmPublic: true` | désactivé par défaut |
| Outils optionnels | trivy : téléchargement de sa base (`--skip-version-check`, rien en hors ligne). osv-scanner : jamais lancé hors ligne ni si des paquets internes sont déclarés. gitleaks, hadolint, kube-linter, helm : 100 % local | `--offline` ou ne pas les installer |

Données qui quittent le poste via l'assistant IA : Copilot lit `resume.md` et `a-verifier.md` (constats et extraits de ± 4 lignes de code). Tous les secrets y sont **masqués** (passage global sur le résultat), les identifiants d'URL sont retirés, et le contenu du dépôt est signalé comme **donnée non fiable** (protection contre l'injection d'instructions). Pour ne transmettre aucun extrait de code : `analyse.extraitsAVerifier: 0`.

## Faux positifs

Créer `allowlists/<nom>.json` (voir `allowlists/exemple.json`) : chaque exclusion exige une **justification** et peut expirer. Les constats exclus restent visibles dans la section 5 du rapport.

## Faire évoluer l'outil avec Copilot

Ouvrez le dossier `skill-analyse` dans VS Code : Copilot charge automatiquement `.github/copilot-instructions.md` (règles impératives et plan du code). Le fonctionnement détaillé est dans [`docs/GUIDE-DEVELOPPEMENT.md`](docs/GUIDE-DEVELOPPEMENT.md).

Deux prompts sont fournis (Copilot Chat, mode Agent) :
- `/calibrer-sur-mes-projets fe01 <url>` : analyse un de vos projets, classe chaque constat (vrai problème / faux positif) et propose les ajustements (configuration, exclusions, règles), puis les applique avec tests après votre validation ;
- `/nouvelle-regle <ce qu'il faut détecter>` : ajoute une vérification en respectant les conventions (règle, test, documentation).

## Transfert vers un autre poste

Privilégier un **dépôt GitLab** (`git push`) : le `.gitignore` exclut déjà les fichiers générés. Pour une archive :

```powershell
powershell -ExecutionPolicy Bypass -File toolspackage.ps1   # crée ..skill-analyse.zip sans tests.tmp, reports, workspace
```

Ne jamais archiver `tests.tmp` : il contient les faux projets piégés générés par les tests (détectés comme virus par les antivirus de messagerie). Les messageries bloquent aussi souvent les pièces jointes contenant des `.js` ou `.ps1`, même compressés.

## Tests

```powershell
npm test
```

Trois suites :
- `tests/run-tests.js` : génère à la volée des projets piégés (fe, bff, helm, dépôt git avec tag non fusionné, push direct, date future, tâche VS Code à l'ouverture, fausse police, consignes IA cachées, GlassWorm, lockfile falsifié, version compromise…) et un projet propre ; vérifie que chaque règle attendue se déclenche, que le projet propre obtient une bonne note, le profil helm et le mode lot ;
- `tests/securite.js` : aucune connexion en hors ligne, aucun secret dans les rapports, tokens jamais envoyés à un hôte non prévu ;
- `tests/gitlab-mock.js` : contrôles GitLab (MR, approbations, protections, webhooks, miroirs, clés, tokens, variables CI) contre une API simulée.

### Maintenir la liste des IOC

`rules/ioc.json` contient les versions de paquets compromises connues, les noms de fichiers et les domaines d'attaque utilisés **hors ligne**. Ajoutez-y les versions citées dans les avis de sécurité (format `"paquet": ["version", …]`). En ligne, la base OSV (identifiants `MAL-…`) complète automatiquement cette liste.

## Limites

- Analyse statique par motifs : un code malveillant très bien dissimulé peut échapper aux règles ; les points 🔎 demandent un jugement.
- Lockfile yarn / pnpm : signalé, analyse transitive non couverte.
- Sans `GITLAB_TOKEN`, approbations et pushs directs ne sont qu'estimés depuis l'historique git.
- Les règles d'approbation détaillées nécessitent une édition payante de GitLab.
