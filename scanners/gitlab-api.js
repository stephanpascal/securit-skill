'use strict';
const { getJson } = require('../lib/net');
const { makeFinding } = require('../lib/finding');
const { daysAgo, truncate, globToRegex, isInternalHost } = require('../lib/util');
const { sanitizeUrl } = require('../lib/sanitize');

const L = 'gitlab';
const R = {
  NO_TOKEN: { id: 'GITLAB_API_INDISPONIBLE', sev: 'info', title: 'Contrôles GitLab non effectués', desc: 'Token absent ou API inaccessible : approbations, merge requests et protections non vérifiées.', fix: 'Définir la variable d\'environnement GITLAB_TOKEN (droit read_api).' },
  DEFAULT_UNPROTECTED: { id: 'GITLAB_BRANCHE_NON_PROTEGEE', sev: 'critical', title: 'Branche principale non protégée', desc: 'N\'importe quel développeur peut pousser directement (ou forcer) sur cette branche.', fix: 'Protéger la branche : push « No one », merge « Maintainers ».' },
  FORCE_PUSH: { id: 'GITLAB_PUSH_FORCE_AUTORISE', sev: 'high', title: 'Push forcé autorisé sur une branche protégée', desc: 'L\'historique de la branche peut être réécrit (suppression de traces, remplacement de code).', fix: 'Désactiver « Allowed to force push ».' },
  DEV_PUSH: { id: 'GITLAB_PUSH_DIRECT_AUTORISE', sev: 'high', title: 'Push direct autorisé sur une branche protégée', desc: 'Des utilisateurs peuvent pousser sans merge request, donc sans revue.', fix: 'Mettre « Allowed to push » à « No one ».' },
  NO_PROTECTED_TAGS: { id: 'GITLAB_TAGS_NON_PROTEGES', sev: 'medium', title: 'Aucun tag protégé', desc: 'Tout développeur peut créer un tag de version (x.y.z) pointant vers n\'importe quel commit, y compris non fusionné.', fix: 'Protéger les tags (motif * ou [0-9]*) : création réservée aux Maintainers ou à la CI.' },
  APPROVALS_ZERO: { id: 'GITLAB_AUCUNE_APPROBATION_REQUISE', sev: 'high', title: 'Aucune approbation requise pour fusionner', desc: 'Une merge request peut être fusionnée sans qu\'aucun relecteur ne l\'ait approuvée.', fix: 'Exiger au moins une approbation (règle d\'approbation).' },
  AUTHOR_APPROVAL: { id: 'GITLAB_AUTO_APPROBATION_AUTORISEE', sev: 'high', title: 'L\'auteur peut approuver sa propre merge request', desc: 'Une seule personne peut écrire, approuver et fusionner du code.', fix: 'Désactiver « Prevent approval by author » = activé.' },
  COMMITTER_APPROVAL: { id: 'GITLAB_APPROBATION_COMMITTER_AUTORISEE', sev: 'medium', title: 'Les committers peuvent approuver', desc: 'Une personne ayant ajouté des commits à la MR peut l\'approuver.', fix: 'Activer « Prevent approvals by users who add commits ».' },
  NO_RESET: { id: 'GITLAB_APPROBATIONS_NON_REINITIALISEES', sev: 'medium', title: 'Approbations conservées après un nouveau push', desc: 'Du code peut être ajouté après l\'approbation sans nouvelle revue.', fix: 'Activer « Remove all approvals when commits are added ».' },
  MR_NO_APPROVAL: { id: 'GITLAB_MR_FUSIONNEE_SANS_APPROBATION', sev: 'high', review: true, title: 'Merge request fusionnée sans approbation', desc: 'Le code a été fusionné sur une branche protégée sans qu\'aucun relecteur ne l\'approuve.', fix: 'Relire a posteriori le contenu de la MR.' },
  MR_SELF_MERGE: { id: 'GITLAB_MR_AUTO_FUSIONNEE', sev: 'high', review: true, title: 'Merge request fusionnée par son propre auteur sans autre approbation', desc: 'L\'auteur a fusionné sa propre MR sans approbation d\'une autre personne.', fix: 'Relire a posteriori ; imposer une approbation par une autre personne.' },
  MR_SELF_APPROVED: { id: 'GITLAB_MR_AUTO_APPROUVEE', sev: 'high', review: true, title: 'Merge request approuvée par son auteur', desc: 'L\'auteur figure parmi les approbateurs de sa propre MR.', fix: 'Interdire l\'auto-approbation.' },
  MR_AUTO_MERGE: { id: 'GITLAB_MR_FUSION_AUTOMATIQUE', sev: 'low', review: true, title: 'Merge request fusionnée automatiquement au succès du pipeline', desc: 'Fusion déclenchée automatiquement : à vérifier si combinée à une absence d\'approbation.', fix: 'Vérifier les approbations.' },
  COMMIT_NO_MR: { id: 'GITLAB_COMMIT_SANS_MR', sev: 'critical', review: true, title: 'Commit présent sur une branche protégée sans aucune merge request (push direct confirmé)', desc: 'GitLab ne connaît aucune merge request contenant ce commit : il a été poussé directement, sans revue.', fix: 'Identifier l\'auteur du push (événements ci-dessous) et relire le commit.' },
  PUSH_PROTECTED: { id: 'GITLAB_PUSH_SUR_BRANCHE_PROTEGEE', sev: 'high', review: true, title: 'Push direct sur une branche protégée (événement GitLab)', desc: 'Un utilisateur a poussé directement sur la branche, hors fusion de merge request.', fix: 'Vérifier le contenu poussé.' },
  FORCE_PUSH_EVENT: { id: 'GITLAB_PUSH_FORCE_PROBABLE', sev: 'high', review: true, title: 'Push sans nouveau commit sur une branche protégée (push forcé probable)', desc: 'Un push sans commit sur une branche existante correspond souvent à une réécriture d\'historique.', fix: 'Comparer l\'état avant/après.' },
  TAG_EVENT: { id: 'GITLAB_TAG_CREE_HORS_CI', sev: 'info', review: true, title: 'Création de tag par un utilisateur', desc: 'Liste des tags créés sur la période et de leurs auteurs.', fix: 'Vérifier que les créateurs sont habilités.' },
  TAG_REMOVED_EVENT: { id: 'GITLAB_TAG_SUPPRIME', sev: 'medium', review: true, title: 'Suppression de tag', desc: 'Un tag a été supprimé (possible remplacement d\'une version publiée).', fix: 'Vérifier la raison.' },
  PIPELINE_SKIP: { id: 'GITLAB_FUSION_SANS_PIPELINE_REQUIS', sev: 'low', title: 'La fusion n\'exige pas un pipeline réussi', desc: 'Du code peut être fusionné sans passer les contrôles automatiques.', fix: 'Activer « Pipelines must succeed ».' },
  HOOK_EXT: { id: 'GITLAB_WEBHOOK_EXTERNE', sev: 'high', review: true, title: 'Webhook vers un hôte externe', desc: 'Chaque événement coché (push, merge request, pipeline…) est envoyé à cet hôte, avec le contenu des commits et messages : canal d\'exfiltration discret.', fix: 'Vérifier le destinataire ; supprimer le webhook s\'il n\'est pas connu.' },
  HOOK_NOSSL: { id: 'GITLAB_WEBHOOK_SANS_TLS', sev: 'medium', title: 'Webhook sans vérification TLS ou en HTTP', desc: 'Les données envoyées peuvent être interceptées.', fix: 'Utiliser HTTPS avec vérification du certificat.' },
  MIRROR: { id: 'GITLAB_MIROIR_DISTANT', sev: 'high', review: true, title: 'Miroir distant : le dépôt est recopié vers un autre serveur', desc: 'Tout le code (et son historique) est poussé automatiquement vers cette destination.', fix: 'Vérifier la destination ; supprimer le miroir s\'il n\'est pas connu.' },
  DEPLOY_KEY_PUSH: { id: 'GITLAB_CLE_DEPLOIEMENT_ECRITURE', sev: 'medium', review: true, title: 'Clé de déploiement avec droit d\'écriture', desc: 'Une clé SSH permet de pousser du code sans compte utilisateur ni MR (accès persistant difficile à tracer).', fix: 'Limiter les clés de déploiement à la lecture, sauf besoin documenté.' },
  TOKEN_NOEXP: { id: 'GITLAB_TOKEN_PROJET_SANS_EXPIRATION', sev: 'medium', review: true, title: 'Token de projet actif à droits élevés ou sans expiration', desc: 'Un token de projet (api / write_repository) reste valide longtemps : accès persistant en cas de fuite.', fix: 'Réduire les droits et fixer une expiration courte.' },
  VAR_UNPROTECTED: { id: 'GITLAB_VARIABLE_CI_EXPOSEE', sev: 'medium', title: 'Variable CI sensible non masquée ou non protégée', desc: 'Une variable dont le nom évoque un secret est lisible dans les journaux (non masquée) ou utilisable depuis n\'importe quelle branche, y compris une branche d\'attaquant (non protégée).', fix: 'Cocher « Masked » et « Protected » (la valeur n\'est jamais lue par cet outil).' },
  PUBLIC: { id: 'GITLAB_PROJET_PUBLIC', sev: 'high', review: true, title: 'Projet visible publiquement', desc: 'Le code, l\'historique et éventuellement les pipelines sont accessibles sans authentification.', fix: 'Passer le projet en « Private » ou « Internal » si ce n\'est pas voulu.' },
  NO_PERM: { id: 'GITLAB_CONTROLE_DROITS_INSUFFISANTS', sev: 'info', title: 'Contrôles de plateforme non effectués (droits insuffisants)', desc: 'Webhooks, miroirs, clés de déploiement, tokens et variables CI ne sont lisibles qu\'avec le rôle Maintainer.', fix: 'Lancer l\'audit avec un token d\'un Maintainer du projet pour ces contrôles.' },
};
const SECRET_VAR = /(TOKEN|SECRET|PASSWORD|PASSWD|PWD|API_?KEY|PRIVATE|CREDENTIAL|AUTH)/i;
for (const r of Object.values(R)) r.cat = L;

const ACCESS = { 0: 'Personne', 30: 'Developers', 40: 'Maintainers', 60: 'Admin' };

async function fetchAll(base, path, headers, maxItems, notes) {
  const out = [];
  let page = 1;
  while (out.length < maxItems) {
    const sep = path.includes('?') ? '&' : '?';
    const r = await getJson(`${base}${path}${sep}per_page=100&page=${page}`, { headers, timeout: 20000 });
    if (r.status === 401 || r.status === 403) throw Object.assign(new Error('accès refusé (' + r.status + ')'), { status: r.status });
    if (r.status === 404) throw Object.assign(new Error('introuvable (404)'), { status: 404 });
    if (!Array.isArray(r.json)) break;
    out.push(...r.json);
    const next = r.headers['x-next-page'];
    if (!next) break;
    page = Number(next);
  }
  if (out.length >= maxItems && notes) notes.push(`${path.split('?')[0]} : limite de ${maxItems} éléments atteinte.`);
  return out.slice(0, maxItems);
}

module.exports = {
  id: 'gitlab-api',
  label: 'GitLab : merge requests, approbations, protections, événements',
  category: L,
  controls: [
    'Protection des branches principales : push direct, push forcé, branche non protégée',
    'Tags protégés',
    'Règles d\'approbation : approbation requise, auto-approbation, approbation par les committers, réinitialisation après push (selon l\'édition GitLab)',
    'Merge requests fusionnées sur la période : sans approbation, fusionnées par leur auteur, auto-approuvées, fusion automatique',
    'Commits des branches protégées sans aucune merge request (push direct confirmé)',
    'Événements : pushs directs sur branches protégées, push forcé probable, création/suppression de tags',
    'Plateforme (rôle Maintainer) : webhooks vers l\'extérieur, miroirs distants, clés de déploiement en écriture, tokens de projet, variables CI sensibles non masquées / non protégées',
    'Visibilité publique du projet',
  ],
  async run(ctx) {
    const findings = [];
    const notes = [];
    const tokenEnv = ctx.config.gitlab.tokenEnv || 'GITLAB_TOKEN';
    const token = process.env[tokenEnv];
    const gl = ctx.gitlab;
    if (ctx.options.noApi) return { findings, status: 'non exécuté', notes: ['Désactivé (--no-api).'] };
    if (!gl || !gl.projectPath) return { findings, status: 'non exécuté', notes: ['URL GitLab non fournie (analyse d\'un dossier local).'] };
    if (ctx.offline || !token || !ctx.network.gitlab) {
      const why = ctx.offline ? 'mode hors ligne' : !token ? `variable ${tokenEnv} absente` : 'API GitLab inaccessible';
      findings.push(makeFinding(R.NO_TOKEN, { evidence: why }));
      return { findings, status: 'non exécuté', notes: [`Contrôles GitLab non effectués : ${why}.`] };
    }
    const base = (ctx.config.gitlab.url || `https://${gl.host}`).replace(/\/$/, '') + '/api/v4';
    // Le token n'est envoyé qu'en HTTPS et qu'à l'instance GitLab du projet (et à celle configurée, si elle l'est).
    let apiHost = '';
    try { apiHost = new URL(base).host.toLowerCase(); } catch { /* ignore */ }
    if (!/^https:\/\//i.test(base) || apiHost.split(':')[0] !== String(gl.host).toLowerCase()) {
      const why = !/^https:\/\//i.test(base) ? 'gitlab.url n\'est pas en HTTPS' : `l'hôte du projet (${gl.host}) diffère de l'instance configurée (${apiHost})`;
      findings.push(makeFinding(R.NO_TOKEN, { evidence: why }));
      return { findings, status: 'non exécuté', notes: [`Token GitLab non envoyé : ${why}.`] };
    }
    const headers = { 'PRIVATE-TOKEN': token };
    const pid = encodeURIComponent(gl.projectPath);
    const since = daysAgo(ctx.options.days || ctx.config.git.periodeJours).toISOString();
    let status = 'ok';
    const info = {};

    const meta = await getJson(`${base}/metadata`, { headers }).catch(() => null);
    if (meta && meta.json) info.version = `${meta.json.version}${meta.json.enterprise ? ' (édition payante)' : ' (édition gratuite / CE)'}`;
    const proj = await getJson(`${base}/projects/${pid}`, { headers });
    if (proj.status !== 200 || !proj.json) {
      notes.push(`Projet introuvable ou accès refusé via l'API (HTTP ${proj.status}).`);
      return { findings: [makeFinding(R.NO_TOKEN, { evidence: `HTTP ${proj.status}` })], status: 'non exécuté', notes };
    }
    const p = proj.json;
    const id = p.id;
    info.projet = p.path_with_namespace; info.brancheParDefaut = p.default_branch; info.methodeMerge = p.merge_method; info.squash = p.squash_option;
    if (p.only_allow_merge_if_pipeline_succeeds === false) findings.push(makeFinding(R.PIPELINE_SKIP, { evidence: 'only_allow_merge_if_pipeline_succeeds = false' }));

    // Protections de branches
    const protRes = ctx.config.git.branchesProtegees.map(globToRegex);
    let protectedBranches = [];
    try {
      protectedBranches = await fetchAll(base, `/projects/${id}/protected_branches`, headers, 100);
      info.branchesProtegees = protectedBranches.map(b => ({ nom: b.name, push: (b.push_access_levels || []).map(a => a.access_level_description || ACCESS[a.access_level]).join(', '), merge: (b.merge_access_levels || []).map(a => a.access_level_description || ACCESS[a.access_level]).join(', '), pushForce: !!b.allow_force_push }));
      const names = protectedBranches.map(b => globToRegex(b.name));
      if (p.default_branch && !names.some(re => re.test(p.default_branch))) findings.push(makeFinding(R.DEFAULT_UNPROTECTED, { evidence: p.default_branch }));
      for (const b of protectedBranches) {
        if (b.allow_force_push) findings.push(makeFinding(R.FORCE_PUSH, { evidence: b.name }));
        const pushLevels = (b.push_access_levels || []);
        if (pushLevels.some(a => a.access_level === 30 || a.user_id || a.group_id)) findings.push(makeFinding(R.DEV_PUSH, { evidence: `${b.name} : push autorisé pour ${pushLevels.map(a => a.access_level_description || ACCESS[a.access_level]).join(', ')}` }));
        else if (pushLevels.some(a => a.access_level === 40)) findings.push(makeFinding(R.DEV_PUSH, { severity: 'low', evidence: `${b.name} : push direct autorisé pour les Maintainers` }));
      }
    } catch (e) { notes.push('Protections de branches non lisibles : ' + e.message); status = 'partiel'; }
    try {
      const pt = await fetchAll(base, `/projects/${id}/protected_tags`, headers, 100);
      info.tagsProteges = pt.map(t => t.name);
      if (!pt.length) findings.push(makeFinding(R.NO_PROTECTED_TAGS, { evidence: 'Aucun motif de tag protégé' }));
    } catch (e) { notes.push('Tags protégés non lisibles : ' + e.message); }

    // Règles d'approbation (éditions payantes)
    const ap = await getJson(`${base}/projects/${id}/approvals`, { headers }).catch(() => null);
    if (ap && ap.status === 200 && ap.json) {
      const a = ap.json;
      info.approbations = { requises: a.approvals_before_merge, autoApprobationAuteur: a.merge_requests_author_approval, approbationCommitters: !a.merge_requests_disable_committers_approval, reinitialisationApresPush: a.reset_approvals_on_push };
      const rules = await getJson(`${base}/projects/${id}/approval_rules`, { headers }).catch(() => null);
      const required = Math.max(a.approvals_before_merge || 0, ...((rules && Array.isArray(rules.json) ? rules.json : []).map(r => r.approvals_required || 0)));
      info.approbations.requises = required;
      if (!required) findings.push(makeFinding(R.APPROVALS_ZERO, { evidence: 'approvals_required = 0' }));
      if (a.merge_requests_author_approval) findings.push(makeFinding(R.AUTHOR_APPROVAL, { evidence: 'merge_requests_author_approval = true' }));
      if (a.merge_requests_disable_committers_approval === false) findings.push(makeFinding(R.COMMITTER_APPROVAL, { evidence: 'merge_requests_disable_committers_approval = false' }));
      if (a.reset_approvals_on_push === false) findings.push(makeFinding(R.NO_RESET, { evidence: 'reset_approvals_on_push = false' }));
    } else {
      notes.push('Règles d\'approbation non disponibles (édition gratuite ou droits insuffisants) : seules les approbations effectives des MR sont vérifiées.');
    }

    // Plateforme : canaux de sortie et accès persistants (rôle Maintainer requis)
    if (p.visibility === 'public') findings.push(makeFinding(R.PUBLIC, { evidence: `visibility = public — ${p.web_url || ''}` }));
    const internal = (ctx.config.domaines.internes || []).concat([gl.host]);
    const isInt = u => { try { const h = new URL(u).hostname.toLowerCase(); return isInternalHost(h, internal); } catch { return false; } };
    const denied = [];
    const platform = {};
    const tryList = async (path, label) => {
      try { return await fetchAll(base, path, headers, 200); }
      catch (e) { if (e.status === 401 || e.status === 403 || e.status === 404) denied.push(label); else notes.push(`${label} non lisibles : ${e.message}`); return null; }
    };
    const hooks = await tryList(`/projects/${id}/hooks`, 'webhooks');
    if (hooks) {
      platform.webhooks = hooks.map(h => ({ url: sanitizeUrl(h.url), evenements: Object.keys(h).filter(k => /_events$/.test(k) && h[k]).map(k => k.replace(/_events$/, '')), tls: h.enable_ssl_verification !== false }));
      for (const h of hooks) {
        const ev = `${sanitizeUrl(h.url)} — événements : ${Object.keys(h).filter(k => /_events$/.test(k) && h[k]).map(k => k.replace(/_events$/, '')).join(', ') || '?'}`;
        if (!isInt(h.url)) findings.push(makeFinding(R.HOOK_EXT, { evidence: ev }));
        if (h.enable_ssl_verification === false || /^http:/i.test(h.url)) findings.push(makeFinding(R.HOOK_NOSSL, { evidence: ev }));
      }
    }
    const mirrors = await tryList(`/projects/${id}/remote_mirrors`, 'miroirs distants');
    if (mirrors) {
      platform.miroirs = mirrors.map(m => ({ url: sanitizeUrl(m.url), actif: m.enabled }));
      for (const m of mirrors.filter(x => x.enabled)) findings.push(makeFinding(R.MIRROR, { evidence: `${sanitizeUrl(m.url)} (dernière synchro : ${(m.last_successful_update_at || '?').slice(0, 10)})`, severity: isInt(m.url) ? 'medium' : 'high' }));
    }
    const keys = await tryList(`/projects/${id}/deploy_keys`, 'clés de déploiement');
    if (keys) {
      platform.clesDeploiement = keys.map(k => ({ titre: k.title, ecriture: !!k.can_push, creee: (k.created_at || '').slice(0, 10) }));
      for (const k of keys.filter(x => x.can_push)) findings.push(makeFinding(R.DEPLOY_KEY_PUSH, { evidence: `« ${k.title} » créée le ${(k.created_at || '').slice(0, 10)}` }));
    }
    const tokens = await tryList(`/projects/${id}/access_tokens`, 'tokens de projet');
    if (tokens) {
      const now = Date.now();
      platform.tokensProjet = tokens.filter(t => t.active && !t.revoked).map(t => ({ nom: t.name, droits: t.scopes, expire: t.expires_at || null }));
      for (const t of tokens.filter(x => x.active && !x.revoked)) {
        const strong = (t.scopes || []).some(s => /^(api|write_repository|write_registry|sudo)$/.test(s));
        const longLived = !t.expires_at || Date.parse(t.expires_at) - now > 365 * 86400000;
        if (strong && longLived) findings.push(makeFinding(R.TOKEN_NOEXP, { evidence: `« ${t.name} » — droits : ${(t.scopes || []).join(', ')} — expiration : ${t.expires_at || 'aucune'}` }));
      }
    }
    const vars = await tryList(`/projects/${id}/variables`, 'variables CI');
    if (vars) {
      // Seuls le nom et les options sont utilisés : la valeur n'est jamais conservée.
      platform.variablesCI = vars.map(v => ({ nom: v.key, masquee: !!v.masked, protegee: !!v.protected }));
      for (const v of vars.filter(x => SECRET_VAR.test(x.key) && (!x.masked || !x.protected))) {
        findings.push(makeFinding(R.VAR_UNPROTECTED, { evidence: `${v.key} — masquée : ${v.masked ? 'oui' : 'NON'}, protégée : ${v.protected ? 'oui' : 'NON'}` }));
      }
    }
    if (denied.length) findings.push(makeFinding(R.NO_PERM, { evidence: denied.join(', ') }));
    info.plateforme = platform;

    // Merge requests fusionnées
    const mrSummary = [];
    const mergeShas = new Set();
    try {
      const mrs = await fetchAll(base, `/projects/${id}/merge_requests?state=merged&updated_after=${encodeURIComponent(since)}&order_by=updated_at`, headers, ctx.config.gitlab.maxMergeRequests, notes);
      for (const mr of mrs) {
        if (mr.merged_at && mr.merged_at < since) continue;
        const target = mr.target_branch;
        const isProt = protRes.some(re => re.test(target)) || target === p.default_branch;
        [mr.merge_commit_sha, mr.squash_commit_sha, mr.sha].filter(Boolean).forEach(s => mergeShas.add(s));
        if (!isProt) continue;
        let approvers = [];
        const apr = await getJson(`${base}/projects/${id}/merge_requests/${mr.iid}/approvals`, { headers }).catch(() => null);
        if (apr && apr.json && Array.isArray(apr.json.approved_by)) approvers = apr.json.approved_by.map(x => x.user && x.user.username).filter(Boolean);
        const author = mr.author && mr.author.username;
        const merger = (mr.merged_by && mr.merged_by.username) || (mr.merge_user && mr.merge_user.username);
        const ev = `!${mr.iid} « ${truncate(mr.title, 70)} » → ${target} — auteur ${author}, fusionnée par ${merger || '?'} le ${(mr.merged_at || '').slice(0, 10)}, approbateurs : ${approvers.join(', ') || 'aucun'} — ${mr.web_url}`;
        const others = approvers.filter(u => u !== author);
        mrSummary.push({ mr: mr.iid, titre: truncate(mr.title, 70), cible: target, auteur: author, fusionnePar: merger, date: (mr.merged_at || '').slice(0, 10), approbateurs: approvers, url: mr.web_url });
        if (!approvers.length) findings.push(makeFinding(R.MR_NO_APPROVAL, { evidence: ev }));
        else if (approvers.includes(author)) findings.push(makeFinding(R.MR_SELF_APPROVED, { evidence: ev }));
        if (merger && merger === author && !others.length) findings.push(makeFinding(R.MR_SELF_MERGE, { evidence: ev }));
        if ((mr.merge_when_pipeline_succeeds || mr.auto_merge_enabled) && !others.length) findings.push(makeFinding(R.MR_AUTO_MERGE, { evidence: ev }));
      }
    } catch (e) { notes.push('Merge requests non lisibles : ' + e.message); status = 'partiel'; }

    // Commits des branches protégées sans MR (confirmation des pushs directs)
    const skipCommitCheck = ctx.profil && ctx.profil.verifierCommitsSansMR === false;
    const candidates = skipCommitCheck ? [] : (ctx.gitCandidates || []).slice(0, ctx.config.gitlab.maxCommitsVerifies);
    if (skipCommitCheck) notes.push(`Vérification commit par commit des pushs directs désactivée (profil « ${ctx.projectType} »).`);
    const confirmed = [];
    for (const c of candidates) {
      if (mergeShas.has(c.sha)) continue;
      const r = await getJson(`${base}/projects/${id}/repository/commits/${c.sha}/merge_requests`, { headers }).catch(() => null);
      if (r && r.status === 200 && Array.isArray(r.json) && r.json.length === 0) {
        confirmed.push(c.sha);
        findings.push(makeFinding(R.COMMIT_NO_MR, { evidence: `${c.branche} : ${c.commit} ${c.date} ${c.auteur} : ${c.sujet}` }));
      }
    }
    if (!skipCommitCheck && (ctx.gitCandidates || []).length > candidates.length) notes.push('Vérification des commits sans MR limitée (gitlab.maxCommitsVerifies).');

    // Événements de push
    const pushes = [];
    try {
      const evs = await fetchAll(base, `/projects/${id}/events?action=pushed&after=${since.slice(0, 10)}`, headers, 500, notes);
      for (const e of evs) {
        const pd = e.push_data || {};
        const who = e.author_username || (e.author && e.author.username) || '?';
        const date = (e.created_at || '').slice(0, 10);
        if (pd.ref_type === 'tag') {
          if (pd.action === 'created') pushes.push({ type: 'tag créé', ref: pd.ref, par: who, date });
          if (pd.action === 'removed') findings.push(makeFinding(R.TAG_REMOVED_EVENT, { evidence: `Tag ${pd.ref} supprimé par ${who} le ${date}` }));
          continue;
        }
        const isProt = protRes.some(re => re.test(pd.ref || '')) || pd.ref === p.default_branch;
        if (!isProt || pd.action !== 'pushed') continue;
        if (pd.commit_to && mergeShas.has(pd.commit_to)) continue; // fusion de MR via l'interface
        if (pd.commit_count === 0 && pd.commit_from) findings.push(makeFinding(R.FORCE_PUSH_EVENT, { evidence: `${pd.ref} par ${who} le ${date} (${(pd.commit_from || '').slice(0, 10)} → ${(pd.commit_to || '').slice(0, 10)})` }));
        else findings.push(makeFinding(R.PUSH_PROTECTED, { evidence: `${pd.ref} par ${who} le ${date} — ${pd.commit_count} commit(s) — « ${truncate(pd.commit_title || '', 70)} »` }));
        pushes.push({ type: 'push', ref: pd.ref, par: who, date, commits: pd.commit_count });
      }
      const tagPushes = pushes.filter(x => x.type === 'tag créé');
      if (tagPushes.length) findings.push(makeFinding(R.TAG_EVENT, { evidence: tagPushes.slice(0, 15).map(t => `${t.ref} (${t.par}, ${t.date})`).join(' ; ') }));
    } catch (e) { notes.push('Événements non lisibles : ' + e.message); status = 'partiel'; }

    return { findings, status, notes, inventory: { gitlab: Object.assign(info, { mergeRequests: mrSummary.slice(0, 100), evenements: pushes.slice(0, 100), commitsSansMR: confirmed.length }) }, confirmedDirect: confirmed, checkedShas: candidates.map(c => c.sha) };
  },
};
