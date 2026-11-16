---
name: nouvelle-regle
description: Ajouter une vérification à l'outil skill-analyse en respectant ses conventions (règle, test, documentation)
argument-hint: <description de ce qu'il faut détecter>
agent: agent
---

Ajoute à l'outil skill-analyse la vérification suivante : **${input:besoin:ce qu'il faut détecter et pourquoi}**.

Respecte `.github/copilot-instructions.md` et les sections 4, 9 et 11 de `docs/GUIDE-DEVELOPPEMENT.md`.

1. Vérifie d'abord si une règle existante couvre déjà ce besoin (recherche dans `lib/shell-rules.js`, `scanners/*.js`, `config/settings.json`, `rules/`). Si oui, propose plutôt de l'ajuster ou de la configurer.
2. Choisis l'emplacement (SHELL_RULES, NET_RULES, RULES d'un scanner, logique structurelle, contrôle en ligne) et justifie-le.
3. Écris la règle : identifiant `PREFIXE_DESCRIPTION` unique, sévérité argumentée, `title` / `desc` / `fix` en français, `review: true` si un jugement est nécessaire, regex **sans drapeau g**, `mask: true` si la valeur est sensible. Aucune dépendance npm, compatible Node 18, aucun accès réseau hors `lib/net.js`.
4. Ajoute un cas positif dans `tests/fixtures.js` (motifs malveillants découpés avec `J(...)`) et l'identifiant attendu dans `tests/run-tests.js` ; ajoute un cas négatif dans le projet propre si un faux positif est plausible.
5. Mets à jour `controls` du scanner, le tableau « Contrôles effectués » du `README.md` et, si utile, `docs/GUIDE-DEVELOPPEMENT.md`.
6. Lance `npm test` : les trois suites doivent passer et `fe-propre` doit rester noté A ou B. Montre-moi le résultat.
