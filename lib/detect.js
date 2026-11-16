'use strict';
/**
 * Détection du type de projet : fe (Angular), bff (Node.js), helm (déploiement).
 * Le contenu prime ; le nom ne sert que d'indice.
 */

const TYPE_LABEL = { fe: 'Frontend (Angular)', bff: 'BFF (Node.js)', helm: 'Déploiement Helm', inconnu: 'Inconnu' };

function hintFromName(name) {
  const n = String(name || '').toLowerCase();
  if (/(^|[-_.])(fe|front|frontend|ui|web)\d*([-_.]|$)/.test(n) || n.includes('front')) return 'fe';
  if (/(^|[-_.])(bff|back|backend|api)\d*([-_.]|$)/.test(n) || n.includes('bff') || n.includes('back-for-front')) return 'bff';
  if (/(helm|chart|deploy|k8s|kube|infra)/.test(n)) return 'helm';
  return null;
}

function detectType(files, readText, name, forced) {
  const has = re => files.some(f => re.test(f.rel));
  const reasons = [];
  let byContent = 'inconnu';
  if (has(/(^|\/)Chart\.ya?ml$/)) { byContent = 'helm'; reasons.push('Chart.yaml présent'); }
  else if (has(/(^|\/)angular\.json$/)) { byContent = 'fe'; reasons.push('angular.json présent'); }
  else {
    const pkg = files.find(f => f.rel === 'package.json');
    if (pkg) {
      let deps = {};
      try { const j = JSON.parse(readText(pkg) || '{}'); deps = Object.assign({}, j.dependencies, j.devDependencies); } catch { /* ignore */ }
      if (deps['@angular/core']) { byContent = 'fe'; reasons.push('@angular/core dans package.json'); }
      else if (deps.react || deps.vue || deps['@vue/cli-service'] || deps.vite) { byContent = 'fe'; reasons.push('framework frontend dans package.json'); }
      else { byContent = 'bff'; reasons.push('package.json sans framework frontend'); }
    }
  }
  const hint = hintFromName(name);
  const type = forced || (byContent !== 'inconnu' ? byContent : (hint || 'inconnu'));
  return {
    type,
    byContent,
    hint,
    forced: forced || null,
    reasons,
    mismatch: (hint && byContent !== 'inconnu' && hint !== byContent) || (forced && byContent !== 'inconnu' && forced !== byContent),
  };
}

module.exports = { detectType, TYPE_LABEL };
