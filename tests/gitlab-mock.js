'use strict';
/**
 * Test du scanner GitLab avec une API simulée (aucune connexion réseau) :
 * protections, approbations, merge requests, commits sans MR, événements, et contrôles de plateforme.
 */
const net = require('../lib/net');

const SECRET_VALUE = 'valeur-secrete-ne-doit-jamais-apparaitre';
const now = new Date().toISOString();
const routes = {
  '/metadata': { version: '17.5.0', enterprise: true },
  '/projects/grp%2Fapp': { id: 42, path_with_namespace: 'grp/app', default_branch: 'main', merge_method: 'merge', squash_option: 'default_on', only_allow_merge_if_pipeline_succeeds: false, visibility: 'public', web_url: 'https://gitlab.entreprise.fr/grp/app' },
  '/projects/42/protected_branches': [{ name: 'main', allow_force_push: true, push_access_levels: [{ access_level: 30, access_level_description: 'Developers + Maintainers' }], merge_access_levels: [{ access_level: 40 }] }],
  '/projects/42/protected_tags': [],
  '/projects/42/approvals': { approvals_before_merge: 0, merge_requests_author_approval: true, merge_requests_disable_committers_approval: false, reset_approvals_on_push: false },
  '/projects/42/approval_rules': [],
  '/projects/42/merge_requests': [
    { iid: 7, title: 'feat: ajout', target_branch: 'main', author: { username: 'alice' }, merged_by: { username: 'alice' }, merged_at: now, merge_commit_sha: 'aaa111', web_url: 'https://gitlab.entreprise.fr/grp/app/-/merge_requests/7' },
    { iid: 8, title: 'fix: correctif', target_branch: 'main', author: { username: 'bob' }, merged_by: { username: 'carol' }, merged_at: now, merge_commit_sha: 'bbb222' },
  ],
  '/projects/42/merge_requests/7/approvals': { approved_by: [] },
  '/projects/42/merge_requests/8/approvals': { approved_by: [{ user: { username: 'carol' } }] },
  '/projects/42/repository/commits/ccc333/merge_requests': [],
  '/projects/42/repository/commits/aaa111/merge_requests': [{ iid: 7 }],
  '/projects/42/events': [
    { author_username: 'mallory', created_at: now, push_data: { ref: 'main', ref_type: 'branch', action: 'pushed', commit_count: 1, commit_to: 'ccc333', commit_title: 'hotfix direct' } },
    { author_username: 'mallory', created_at: now, push_data: { ref: 'main', ref_type: 'branch', action: 'pushed', commit_count: 0, commit_from: 'ddd444', commit_to: 'eee555' } },
    { author_username: 'mallory', created_at: now, push_data: { ref: '1.2.3', ref_type: 'tag', action: 'removed' } },
  ],
  '/projects/42/hooks': [{ url: 'https://collecte.exemple-externe.com/hook', push_events: true, merge_requests_events: true, enable_ssl_verification: false }],
  '/projects/42/remote_mirrors': [{ url: 'https://*****:*****@github.com/inconnu/copie.git', enabled: true, last_successful_update_at: now }],
  '/projects/42/deploy_keys': [{ title: 'cle-ci', can_push: true, created_at: now }],
  '/projects/42/access_tokens': [{ name: 'bot', active: true, revoked: false, scopes: ['api'], expires_at: null }],
  '/projects/42/variables': [{ key: 'NPM_TOKEN', value: SECRET_VALUE, masked: false, protected: false }, { key: 'APP_COLOR', value: 'bleu', masked: false, protected: false }],
};

let calls = 0;
net.getJson = async (url) => {
  calls++;
  const u = new URL(url);
  const p = u.pathname.replace(/^\/api\/v4/, '');
  if (!(p in routes)) return { status: 404, headers: {}, json: null };
  return { status: 200, headers: {}, json: JSON.parse(JSON.stringify(routes[p])) };
};

const gitlabApi = require('../scanners/gitlab-api');
const { loadConfig } = require('../lib/config');
const { maskDeep } = require('../lib/sanitize');

(async () => {
  process.env.GITLAB_TOKEN = 'jeton-test';
  const cfg = loadConfig();
  cfg.gitlab.url = 'https://gitlab.entreprise.fr';
  const ctx = {
    config: cfg, options: {}, offline: false, network: { gitlab: true }, projectType: 'bff', profil: {},
    gitlab: { host: 'gitlab.entreprise.fr', projectPath: 'grp/app' },
    gitCandidates: [{ sha: 'ccc333', commit: 'ccc333', branche: 'main', date: now.slice(0, 10), auteur: 'mallory', sujet: 'hotfix direct' }, { sha: 'aaa111', commit: 'aaa111', branche: 'main', date: now.slice(0, 10), auteur: 'alice', sujet: 'merge' }],
  };
  const r = await gitlabApi.run(ctx);
  delete process.env.GITLAB_TOKEN;
  const rules = new Set(r.findings.map(f => f.rule));
  const expected = ['GITLAB_PROJET_PUBLIC', 'GITLAB_PUSH_FORCE_AUTORISE', 'GITLAB_PUSH_DIRECT_AUTORISE', 'GITLAB_TAGS_NON_PROTEGES', 'GITLAB_AUCUNE_APPROBATION_REQUISE',
    'GITLAB_AUTO_APPROBATION_AUTORISEE', 'GITLAB_APPROBATION_COMMITTER_AUTORISEE', 'GITLAB_APPROBATIONS_NON_REINITIALISEES', 'GITLAB_FUSION_SANS_PIPELINE_REQUIS',
    'GITLAB_MR_FUSIONNEE_SANS_APPROBATION', 'GITLAB_MR_AUTO_FUSIONNEE', 'GITLAB_COMMIT_SANS_MR', 'GITLAB_PUSH_SUR_BRANCHE_PROTEGEE', 'GITLAB_PUSH_FORCE_PROBABLE', 'GITLAB_TAG_SUPPRIME',
    'GITLAB_WEBHOOK_EXTERNE', 'GITLAB_WEBHOOK_SANS_TLS', 'GITLAB_MIROIR_DISTANT', 'GITLAB_CLE_DEPLOIEMENT_ECRITURE', 'GITLAB_TOKEN_PROJET_SANS_EXPIRATION', 'GITLAB_VARIABLE_CI_EXPOSEE'];
  const missing = expected.filter(e => !rules.has(e));
  let failures = 0;
  const check = (ok, label) => { console.log(`${ok ? '✅' : '❌'} ${label}`); if (!ok) failures++; };
  check(!missing.length, `API GitLab simulée : ${expected.length - missing.length}/${expected.length} contrôles déclenchés${missing.length ? ' — manquants : ' + missing.join(', ') : ''}`);
  check(r.confirmedDirect.length === 1 && r.confirmedDirect[0] === 'ccc333', 'Commit sans MR confirmé uniquement pour le push direct (pas pour le commit de merge)');
  check(!r.findings.some(f => f.rule === 'GITLAB_MR_FUSIONNEE_SANS_APPROBATION' && /!8/.test(f.evidence)), 'MR approuvée par une autre personne non signalée');
  check(!r.findings.some(f => f.rule === 'GITLAB_VARIABLE_CI_EXPOSEE' && /APP_COLOR/.test(f.evidence)), 'Variable non sensible non signalée');
  const out = JSON.stringify(maskDeep({ findings: r.findings, inventory: r.inventory }));
  check(!out.includes(SECRET_VALUE), 'Valeur des variables CI jamais présente dans les résultats');
  check(calls > 0, `Aucun appel réseau réel (${calls} appels servis par la simulation)`);
  // Profil helm : pas de vérification commit par commit
  calls = 0;
  process.env.GITLAB_TOKEN = 'jeton-test';
  const r2 = await gitlabApi.run(Object.assign({}, ctx, { projectType: 'helm', profil: { verifierCommitsSansMR: false } }));
  delete process.env.GITLAB_TOKEN;
  check(!r2.findings.some(f => f.rule === 'GITLAB_COMMIT_SANS_MR'), 'Profil helm : vérification commit par commit désactivée');
  console.log(failures ? `\n${failures} test(s) GitLab en échec` : '\nTous les tests GitLab passent.');
  process.exit(failures ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
