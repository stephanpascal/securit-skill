# Plan et décisions — skill-analyse

## Besoin

Auditer, un projet à la fois (nom + URL GitLab), trois types de projets : frontend Angular, BFF Node.js, chart Helm. Détecter backdoors, code malveillant, scripts exécutés à l'installation npm (y compris dépendances transitives), Dockerfile et configurations serveur détournés, comportements git suspects (tags non fusionnés, pushs directs, merges sans approbation). Produire une note rapide puis un détail structuré, en consommant le moins de tokens IA possible.

## Décisions

| Sujet | Décision |
|---|---|
| Langage | Node.js ≥ 18 sans aucune dépendance (poste sans droits admin, CI GitLab possible) |
| Assistant | GitHub Copilot (skill + prompt), variante Claude Code |
| Entrée | `nom` + `URL GitLab`, clone sécurisé, suppression après analyse |
| Exécution | Jamais de code du projet analysé |
| Réseau | En ligne par défaut, bascule hors ligne automatique ; proxy et CA d'entreprise supportés |
| Registre npm | Artifactory d'entreprise (URL à renseigner dans `settings.local.json`) |
| Outils externes | Optionnels, détectés automatiquement, téléchargeables sans admin |
| Git | Branches protégées `main/master/develop`, tags `x.y.z(-a)`, 30 jours configurables, signature désactivée |
| Workflow de merge | Merges vers les branches principales via l'interface GitLab → un commit non-merge sur la ligne principale = push direct probable (confirmé par l'API) |
| Rapport | Markdown (lisible par Copilot et humain) + JSON, toujours produit, en français |
| Notation | Score /100 + note A–E avec plafonds ; `--ci` échoue à partir de D |
| Dépôts Helm | Surveillance allégée des merges / commits directs (profil helm : constats en Info, hors note) |
| Multi-projets | audit-lot.js : paires nom/URL ou fichier, synthèse triée par risque |
| Faux positifs | `allowlists/<nom>.json` avec justification obligatoire |

## Architecture

```
audit.js                 point d'entrée CLI (un projet)
audit-lot.js             plusieurs projets + synthèse consolidée
lib/                     socle : config, clone sécurisé, parcours, règles, réseau, tar, notation, rapport, orchestrateur
scanners/                structure, secrets, dockerfile, shell-scripts, source-code, server-config,
                         package-json, dependencies, k8s-helm, git-local, gitlab-api, external-tools
rules/                   paquets populaires (typosquatting)
config/                  settings.json (+ settings.local.json non versionné)
allowlists/              exclusions justifiées par projet
integration/             skill/prompt Copilot, skill Claude, install.ps1
tools/                   setup-tools.ps1 (outils optionnels → tools/bin)
ci/                      exemple de job GitLab CI
tests/                   projets piégés générés + vérification des détections
```

## Ajouts v1.1 (attaques 2025-2026)

Scanners « IDE et assistants IA » et « Unicode » ; détournement d'assistants IA (s1ngularity), comportements de ver (Shai-Hulud), C2 blockchain (EtherHiding), IOC hors ligne (`rules/ioc.json`), lockfile falsifié, dépendances HTTP (PhantomRaven) ; en ligne : slopsquatting, éditeur inconnu sur version récente, perte de provenance, manifest confusion ; GitLab : webhooks, miroirs, clés de déploiement, tokens, variables CI, projet public ; `.dockerignore`, source maps, CSP, service worker. Test GitLab sur API simulée.

## Pistes d'évolution

- Inventaire des capacités de chaque dépendance (réseau, shell, fichiers, variables d'environnement) par analyse de tout le code de l'archive.
- Vérification cryptographique des signatures et attestations du registre (équivalent de `npm audit signatures`).
- Analyse transitive des lockfiles yarn / pnpm.
- Comparaison du contenu d'une archive npm avec le dépôt git source déclaré.
- Contrôles croisés entre projets (ports EXPOSE du fe/bff vs Service/containerPort du chart Helm, image construite vs image déployée).
- Journal d'audit GitLab (édition payante) pour les pushs forcés et changements de protections.
