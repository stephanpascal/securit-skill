'use strict';
const { git, tryGit } = require('../lib/git');
const { makeFinding } = require('../lib/finding');
const { scanLines } = require('../lib/patterns');
const { SHELL_RULES } = require('../lib/shell-rules');
const { globToRegex, daysAgo, truncate } = require('../lib/util');
const sourceCode = require('./source-code');
const secrets = require('./secrets');

const G = 'git';
const R = {
  TAG_NOT_MERGED: { id: 'GIT_TAG_NON_FUSIONNE', sev: 'high', review: true, title: 'Tag pointant vers un commit absent de toutes les branches protégées', desc: 'Le code livré par ce tag n\'a jamais été fusionné dans une branche protégée : il a pu échapper à la revue de code.', fix: 'Comparer le tag à la branche principale (détail ci-dessous) et vérifier qui l\'a créé.' },
  TAG_NOT_MERGED_SENSITIVE: { id: 'GIT_TAG_NON_FUSIONNE_SENSIBLE', sev: 'critical', review: true, title: 'Tag non fusionné modifiant des fichiers sensibles', desc: 'Le tag contient des modifications de fichiers sensibles (package.json, Dockerfile, CI, configuration serveur…) absentes des branches protégées.', fix: 'Ne pas déployer ce tag avant analyse ; vérifier les commits listés.' },
  TAG_FORMAT: { id: 'GIT_TAG_FORMAT', sev: 'low', title: 'Tag hors convention de nommage', desc: 'Le tag ne respecte pas le format attendu (x.y.z ou x.y.z-a).', fix: 'Vérifier la légitimité du tag.' },
  TAG_MOVED: { id: 'GIT_TAG_DEPLACE', sev: 'critical', title: 'Tag déplacé depuis la dernière analyse', desc: 'Le même tag pointe désormais vers un autre commit : le contenu d\'une version déjà livrée a été remplacé.', fix: 'Investiguer immédiatement (qui a forcé le tag, quel contenu a changé).' },
  TAG_DELETED: { id: 'GIT_TAG_SUPPRIME', sev: 'medium', review: true, title: 'Tag supprimé depuis la dernière analyse', desc: 'Un tag existant lors de l\'analyse précédente a disparu.', fix: 'Vérifier la raison de la suppression.' },
  REWRITTEN: { id: 'GIT_HISTORIQUE_REECRIT', sev: 'critical', title: 'Historique d\'une branche protégée réécrit (push forcé)', desc: 'Le commit de tête connu lors de l\'analyse précédente n\'est plus un ancêtre de la branche : l\'historique a été réécrit.', fix: 'Comparer les deux versions de la branche pour identifier ce qui a été retiré ou ajouté.' },
  DIRECT: { id: 'GIT_COMMIT_DIRECT_PROBABLE', sev: 'medium', review: true, title: 'Commit sur une branche protégée sans merge (push direct probable)', desc: 'Avec un workflow de merge via GitLab, la ligne principale ne contient que des commits de merge. Ce commit a probablement été poussé directement. (Confirmé par l\'API GitLab si disponible.)', fix: 'Vérifier qui a poussé ce commit et pourquoi il n\'est pas passé par une merge request.' },
  MERGE_NO_MR: { id: 'GIT_MERGE_HORS_GITLAB', sev: 'medium', review: true, title: 'Merge sur une branche protégée sans référence à une merge request', desc: 'Ce commit de merge ne contient pas « See merge request » : il a probablement été fait en local puis poussé.', fix: 'Vérifier qu\'une revue a eu lieu.' },
  FUTURE: { id: 'GIT_DATE_FUTURE', sev: 'high', review: true, title: 'Commit daté dans le futur', desc: 'Une date dans le futur indique une manipulation des dates (masquage dans l\'historique).', fix: 'Investiguer le commit.' },
  BACKDATED: { id: 'GIT_DATE_INCOHERENTE', sev: 'medium', review: true, title: 'Commit antérieur à son parent', desc: 'La date du commit est antérieure à celle de son parent : antidatage possible.', fix: 'Vérifier le commit.' },
  DATE_GAP: { id: 'GIT_ECART_DATES', sev: 'low', review: true, title: 'Écart important entre date d\'auteur et date de commit', desc: 'Le commit a été créé longtemps avant d\'être intégré (cherry-pick, rebase ou dissimulation).', fix: 'Vérifier le contexte.' },
  EXTERNAL_EMAIL: { id: 'GIT_EMAIL_EXTERNE', sev: 'medium', review: true, title: 'Auteur ou committer avec une adresse hors du domaine de l\'entreprise', desc: 'Un commit sur une branche protégée provient d\'une identité externe ou mal configurée (usurpation possible).', fix: 'Vérifier l\'identité de la personne.' },
  NEW_AUTHOR_SENSITIVE: { id: 'GIT_NOUVEL_AUTEUR_FICHIERS_SENSIBLES', sev: 'medium', review: true, title: 'Nouvel auteur modifiant des fichiers sensibles', desc: 'Un auteur jamais vu avant la période analysée modifie des fichiers sensibles.', fix: 'Relire ces modifications.' },
  MISLEADING: { id: 'GIT_MESSAGE_TROMPEUR', sev: 'medium', review: true, title: 'Message de commit anodin pour une modification importante de fichiers sensibles', desc: 'Un message type « fix typo » ou « bump » accompagne une modification conséquente de fichiers sensibles : technique de dissimulation.', fix: 'Relire le diff du commit.' },
  GITIGNORE_BUILD: { id: 'GIT_GITIGNORE_ET_BUILD', sev: 'medium', review: true, title: '.gitignore modifié en même temps qu\'un script de build', desc: 'Schéma observé dans l\'attaque xz-utils : un fichier est exclu du suivi en même temps que le build est modifié.', fix: 'Relire le commit.' },
  BINARY_TEST: { id: 'GIT_BINAIRE_DANS_TESTS', sev: 'medium', review: true, title: 'Fichier binaire ajouté dans des données de test', desc: 'Dans l\'attaque xz-utils, la charge malveillante était cachée dans des fichiers de test binaires.', fix: 'Vérifier le fichier et ce qui le lit.' },
  BRANCH_ONLY_CODE: { id: 'GIT_CODE_HORS_BRANCHE_PRINCIPALE', sev: 'high', review: true, title: 'Motif dangereux introduit dans un commit absent de la branche analysée', desc: 'Un commit récent présent sur une autre branche ou un tag contient un motif dangereux.', fix: 'Identifier la branche/le tag et empêcher sa fusion ou son déploiement.' },
  HISTORY_SECRET: { id: 'GIT_SECRET_HISTORIQUE', sev: 'high', title: 'Secret présent dans l\'historique récent', desc: 'Un secret a été commité ; même supprimé ensuite, il reste lisible dans l\'historique.', fix: 'Révoquer le secret ; le retirer de l\'historique si nécessaire.' },
};
for (const r of Object.values(R)) r.cat = G;

const SENSITIVE = /(^|\/)(package\.json|package-lock\.json|npm-shrinkwrap\.json|\.npmrc|\.yarnrc(\.yml)?|\.pnpmfile\.cjs|Dockerfile[^/]*|Containerfile|\.gitlab-ci\.yml|angular\.json|proxy\.conf[^/]*|[^/]*\.conf|\.htaccess|Chart\.yaml|values[^/]*\.ya?ml|\.husky\/[^/]+|[^/]*\.(sh|ps1|bat|cmd)|main\.ts|index\.html|server\.(js|ts)|app\.(js|ts)|\.gitmodules|\.gitattributes)$|(^|\/)templates\/[^/]+$|(^|\/)\.gitlab\//;
const BUILD_FILE = /(^|\/)(package\.json|Dockerfile[^/]*|Makefile|angular\.json|webpack[^/]*\.js|vite\.config\.\w+|[^/]*\.sh|\.gitlab-ci\.yml|tsconfig[^/]*\.json)$/;
const ANODYNE = /^(fix(es|ed)?\s+(a\s+)?typo|typo|lint|linting|format(ting)?|prettier|bump|minor|wip|update|cleanup|clean\s?up|refacto(r|ring)?|chore|misc|small fix|tweak)\b/i;
const HISTORY_RULES = SHELL_RULES.concat(sourceCode.MINIFIED_RULES).filter(r => ['critical', 'high'].includes(r.sev));
const HISTORY_SECRET_RULES = secrets.RULES.filter(r => r.sev === 'critical');

function short(sha) { return (sha || '').slice(0, 10); }

function parseRecords(out, fields) {
  return out.split('\x1e').map(s => s.replace(/^\s+/, '')).filter(Boolean).map(rec => {
    const parts = rec.split('\x1f');
    const o = {};
    fields.forEach((f, i) => { o[f] = (parts[i] || '').trim(); });
    o._rest = parts.slice(fields.length).join('\x1f');
    return o;
  });
}

function emailAllowed(email, domains) {
  if (!domains.length) return true;
  email = (email || '').toLowerCase();
  if (/noreply|no-reply/.test(email)) return true;
  return domains.some(d => email.endsWith('@' + d.toLowerCase().replace(/^@/, '')) || email.endsWith('.' + d.toLowerCase().replace(/^@/, '')));
}

module.exports = {
  id: 'git-local',
  label: 'Historique git (analyse locale)',
  category: G,
  controls: [
    'Tags pointant vers des commits absents des branches protégées (code livré sans merge) et détail des différences',
    'Format des tags (x.y.z / x.y.z-a), tags déplacés ou supprimés depuis la dernière analyse',
    'Historique réécrit (push forcé) sur les branches protégées depuis la dernière analyse',
    'Commits poussés directement sur une branche protégée, merges faits hors GitLab',
    'Dates incohérentes (futur, antérieures au parent, écart auteur/commit)',
    'Emails hors du domaine de l\'entreprise, nouveaux auteurs modifiant des fichiers sensibles',
    'Messages anodins masquant des modifications sensibles, .gitignore + build (schéma xz-utils), binaires dans les tests',
    'Motifs dangereux et secrets introduits dans les commits récents (y compris sur d\'autres branches et tags)',
  ],
  async run(ctx) {
    const findings = [];
    const notes = [];
    const root = ctx.root;
    if (!ctx.repo || !ctx.repo.isRepo) return { findings, status: 'non exécuté', notes: ['Pas de dépôt git (analyse d\'un dossier).'] };
    if (ctx.repo.shallow) return { findings, status: 'non exécuté', notes: ['Clone superficiel (--shallow) : analyse de l\'historique impossible.'] };
    const cfg = ctx.config.git;
    const days = ctx.options.days || cfg.periodeJours;
    const since = daysAgo(days).toISOString();
    const domains = ctx.config.domaines.emailsDeveloppeurs || [];
    const now = Date.now();

    // ---- Références ----
    const refsRaw = git(['for-each-ref', '--format=%(refname)%1f%(objectname)%1f%(objecttype)%1f%(*objectname)%1f%(creatordate:iso-strict)%1f%(taggername)%1f%(taggeremail)%1e', 'refs/remotes', 'refs/heads', 'refs/tags'], root);
    const refs = parseRecords(refsRaw, ['ref', 'obj', 'type', 'peeled', 'date', 'tagger', 'taggerEmail']);
    let branches = refs.filter(r => r.ref.startsWith('refs/remotes/origin/') && !r.ref.endsWith('/HEAD')).map(r => ({ name: r.ref.slice(20), ref: r.ref, sha: r.obj }));
    if (!branches.length) branches = refs.filter(r => r.ref.startsWith('refs/heads/')).map(r => ({ name: r.ref.slice(11), ref: r.ref, sha: r.obj }));
    const protRes = cfg.branchesProtegees.map(globToRegex);
    let protectedBranches = branches.filter(b => protRes.some(re => re.test(b.name)));
    if (!protectedBranches.length) {
      protectedBranches = branches.filter(b => b.name === ctx.repo.defaultBranch);
      notes.push('Aucune branche protégée configurée trouvée : utilisation de la branche par défaut.');
    }
    const defaultBranch = protectedBranches.find(b => b.name === ctx.repo.defaultBranch) || protectedBranches[0];
    const tags = refs.filter(r => r.ref.startsWith('refs/tags/')).map(r => ({ name: r.ref.slice(10), commit: r.type === 'tag' ? r.peeled : r.obj, date: r.date, tagger: r.tagger, email: (r.taggerEmail || '').replace(/[<>]/g, ''), annotated: r.type === 'tag' }));
    tags.sort((a, b) => (b.date || '').localeCompare(a.date || ''));
    const protRefs = protectedBranches.map(b => b.ref);

    // ---- Comparaison avec l'analyse précédente ----
    const prev = ctx.previous && ctx.previous.git && ctx.previous.git.refs;
    if (prev) {
      for (const [name, commit] of Object.entries(prev.tags || {})) {
        const cur = tags.find(t => t.name === name);
        if (!cur) findings.push(makeFinding(R.TAG_DELETED, { evidence: `Tag ${name} (était ${short(commit)})` }));
        else if (cur.commit !== commit) findings.push(makeFinding(R.TAG_MOVED, { evidence: `Tag ${name} : ${short(commit)} → ${short(cur.commit)}` }));
      }
      for (const [name, sha] of Object.entries(prev.branches || {})) {
        const cur = protectedBranches.find(b => b.name === name);
        if (!cur || cur.sha === sha) continue;
        const exists = tryGit(['cat-file', '-e', sha + '^{commit}'], root) !== null;
        const ancestor = exists && tryGit(['merge-base', '--is-ancestor', sha, cur.sha], root) !== null;
        if (!ancestor) findings.push(makeFinding(R.REWRITTEN, { evidence: `Branche ${name} : tête précédente ${short(sha)} ${exists ? 'n\'est plus un ancêtre' : 'n\'existe plus'} (tête actuelle ${short(cur.sha)})` }));
      }
    }

    // ---- Tags ----
    const tagRe = new RegExp(cfg.formatTag);
    const selected = tags.filter((t, i) => i < cfg.tagsMinimum || (t.date && t.date >= since));
    const tagInfos = [];
    for (const t of selected) {
      const info = { tag: t.name, commit: short(t.commit), date: (t.date || '').slice(0, 10), createur: t.tagger || '(tag léger)', fusionne: true };
      if (!tagRe.test(t.name)) findings.push(makeFinding(R.TAG_FORMAT, { evidence: t.name }));
      if (t.annotated && !emailAllowed(t.email, domains)) findings.push(makeFinding(R.EXTERNAL_EMAIL, { evidence: `Tag ${t.name} créé par ${t.tagger} <${t.email}>` }));
      const containing = protRefs.length ? (tryGit(['for-each-ref', '--contains', t.commit, '--format=%(refname)', ...protRefs], root) || '').trim() : '';
      if (!containing && defaultBranch) {
        info.fusionne = false;
        const base = (tryGit(['merge-base', t.commit, defaultBranch.ref], root) || '').trim();
        const range = base ? `${base}..${t.commit}` : t.commit;
        const commits = parseRecords(tryGit(['log', '--format=%H%x1f%an%x1f%ae%x1f%aI%x1f%s%x1e', '--max-count=50', range], root) || '', ['sha', 'an', 'ae', 'date', 'subject']);
        const files = base ? (tryGit(['diff', '--name-only', base, t.commit], root) || '').split(/\r?\n/).filter(Boolean) : [];
        const sens = files.filter(f => SENSITIVE.test(f));
        info.commitsSpecifiques = commits.length; info.fichiers = files.length; info.fichiersSensibles = sens;
        const ev = `Tag ${t.name} (${short(t.commit)}, ${info.date}, ${info.createur}) — ${commits.length} commit(s) absents de ${defaultBranch.name} par ${[...new Set(commits.map(c => c.an))].join(', ') || '?'} — fichiers : ${(sens.length ? sens : files).slice(0, 8).join(', ')}${files.length > 8 ? '…' : ''}`;
        findings.push(makeFinding(sens.length ? R.TAG_NOT_MERGED_SENSITIVE : R.TAG_NOT_MERGED, { evidence: ev, extra: { commits: commits.slice(0, 10).map(c => `${short(c.sha)} ${c.date.slice(0, 10)} ${c.an} <${c.ae}> : ${c.subject}`) } }));
        if (base) {
          const diff = tryGit(['diff', '--unified=0', '--no-color', base, t.commit], root) || '';
          findings.push(...scanAddedLines(diff, `tag ${t.name}`, ctx, HISTORY_RULES.concat(HISTORY_SECRET_RULES), R.BRANCH_ONLY_CODE));
        }
      }
      tagInfos.push(info);
    }

    // ---- Commits récents sur les branches protégées ----
    const logFields = ['sha', 'parents', 'an', 'ae', 'aDate', 'cn', 'ce', 'cDate', 'subject', 'body'];
    const protCommits = protRefs.length ? parseRecords(tryGit(['log', ...protRefs, `--since=${since}`, `--max-count=${cfg.maxCommits}`, '--format=%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1f%s%x1f%b%x1e'], root) || '', logFields) : [];
    const byDate = new Map(protCommits.map(c => [c.sha, c.cDate]));
    const extEmails = new Map();
    let gapCount = 0; let gapExample = null;
    for (const c of protCommits) {
      const ev = `${short(c.sha)} ${c.cDate.slice(0, 10)} ${c.an} <${c.ae}> : ${truncate(c.subject, 80)}`;
      if (Date.parse(c.aDate) > now + 86400000 || Date.parse(c.cDate) > now + 86400000) findings.push(makeFinding(R.FUTURE, { evidence: ev }));
      const p0 = c.parents.split(' ')[0];
      if (p0 && byDate.has(p0) && Date.parse(c.cDate) + 3600000 < Date.parse(byDate.get(p0))) findings.push(makeFinding(R.BACKDATED, { evidence: `${ev} (parent ${short(p0)} daté ${byDate.get(p0).slice(0, 16)})` }));
      if (Math.abs(Date.parse(c.cDate) - Date.parse(c.aDate)) > 30 * 86400000) { gapCount++; gapExample = gapExample || ev; }
      for (const [who, email] of [[c.an, c.ae], [c.cn, c.ce]]) {
        if (!emailAllowed(email, domains)) { const k = `${who} <${email}>`; extEmails.set(k, (extEmails.get(k) || 0) + 1); }
      }
    }
    if (gapCount) findings.push(makeFinding(R.DATE_GAP, { evidence: `${gapCount} commit(s), ex. : ${gapExample}` }));
    for (const [k, n] of extEmails) findings.push(makeFinding(R.EXTERNAL_EMAIL, { evidence: `${k} — ${n} commit(s) sur branches protégées` }));

    // Ligne principale (first-parent) : commits non-merge et merges sans MR
    const directs = [];
    for (const b of protectedBranches) {
      const fp = parseRecords(tryGit(['log', '--first-parent', b.ref, `--since=${since}`, `--max-count=${cfg.maxCommits}`, '--format=%H%x1f%P%x1f%an%x1f%ae%x1f%cI%x1f%s%x1f%b%x1e'], root) || '', ['sha', 'parents', 'an', 'ae', 'date', 'subject', 'body']);
      for (const c of fp) {
        const isMerge = c.parents.split(' ').filter(Boolean).length > 1;
        const ev = `${b.name} : ${short(c.sha)} ${c.date.slice(0, 10)} ${c.an} <${c.ae}> : ${truncate(c.subject, 80)}`;
        if (!isMerge && c.parents) {
          const files = (tryGit(['diff-tree', '--no-commit-id', '--name-only', '-r', c.sha], root) || '').split(/\r?\n/).filter(Boolean);
          const sens = files.filter(f => SENSITIVE.test(f));
          directs.push({ branche: b.name, sha: c.sha, auteur: c.an, date: c.date, sujet: c.subject, fichiersSensibles: sens });
          findings.push(makeFinding(R.DIRECT, { evidence: ev + (sens.length ? ` — fichiers sensibles : ${sens.slice(0, 5).join(', ')}` : ''), severity: sens.length ? 'high' : 'medium', extra: { sha: c.sha, branche: b.name } }));
        } else if (isMerge && !/See merge request|merge request !\d+/i.test(c.subject + ' ' + c.body)) {
          findings.push(makeFinding(R.MERGE_NO_MR, { evidence: ev, extra: { sha: c.sha, branche: b.name } }));
        }
      }
    }
    if (directs.length > 15) notes.push(`${directs.length} commits non-merge sur la ligne principale : si le projet utilise le fast-forward, ces signalements sont à confirmer par l'API GitLab.`);

    // ---- Tous les commits récents (toutes branches et tags) : fichiers modifiés ----
    const oldAuthors = new Set((tryGit(['log', '--all', `--before=${since}`, '--max-count=20000', '--format=%ae'], root) || '').split(/\r?\n/).map(s => s.trim().toLowerCase()).filter(Boolean));
    const recent = parseRecords(tryGit(['log', '--all', '--no-merges', `--since=${since}`, `--max-count=${cfg.maxCommits}`, '--numstat', '--format=%x1e%H%x1f%an%x1f%ae%x1f%aI%x1f%s%x1f'], root) || '', ['sha', 'an', 'ae', 'date', 'subject']);
    const sensitiveChanges = [];
    for (const c of recent) {
      const stats = c._rest.split(/\r?\n/).map(l => /^(\d+|-)\t(\d+|-)\t(.+)$/.exec(l.trim())).filter(Boolean).map(m => ({ add: m[1], del: m[2], file: m[3] }));
      const sens = stats.filter(s => SENSITIVE.test(s.file));
      const ev = `${short(c.sha)} ${c.date.slice(0, 10)} ${c.an} <${c.ae}> : ${truncate(c.subject, 80)}`;
      if (sens.length) sensitiveChanges.push({ commit: short(c.sha), date: c.date.slice(0, 10), auteur: c.an, sujet: truncate(c.subject, 80), fichiers: sens.map(s => s.file).slice(0, 8) });
      if (sens.length && oldAuthors.size && !oldAuthors.has(c.ae.toLowerCase())) findings.push(makeFinding(R.NEW_AUTHOR_SENSITIVE, { evidence: `${ev} — ${sens.map(s => s.file).slice(0, 5).join(', ')}` }));
      const sensLines = sens.reduce((a, s) => a + (Number(s.add) || 0) + (Number(s.del) || 0), 0);
      if (ANODYNE.test(c.subject) && sens.length && sensLines >= 30) findings.push(makeFinding(R.MISLEADING, { evidence: `${ev} — ${sensLines} lignes modifiées dans ${sens.map(s => s.file).slice(0, 4).join(', ')}` }));
      if (stats.some(s => /(^|\/)\.gitignore$/.test(s.file)) && stats.some(s => BUILD_FILE.test(s.file))) findings.push(makeFinding(R.GITIGNORE_BUILD, { evidence: `${ev} — ${stats.map(s => s.file).slice(0, 6).join(', ')}` }));
      for (const s of stats) if (s.add === '-' && /(^|\/)(tests?|__tests__|spec|fixtures?|testdata|test-data)\//i.test(s.file)) findings.push(makeFinding(R.BINARY_TEST, { evidence: `${ev} — ${s.file}` }));
    }

    // ---- Lignes ajoutées récemment : motifs dangereux hors branche analysée + secrets ----
    const headSet = new Set((tryGit(['rev-list', 'HEAD', `--since=${since}`, `--max-count=${cfg.maxCommits}`], root) || '').split(/\r?\n/).filter(Boolean));
    const patchOut = tryGit(['log', '--all', '--no-merges', `--since=${since}`, `--max-count=${Math.min(cfg.maxCommits, 300)}`, '-p', '--unified=0', '--no-color', '--format=%x1eCOMMIT%x1f%H%x1f%an%x1f%aI%x1f%s'], root) || '';
    for (const chunk of patchOut.split('\x1eCOMMIT').filter(Boolean)) {
      const [, sha, an, date, rest] = chunk.split('\x1f');
      if (!sha) continue;
      const nl = rest.indexOf('\n');
      const subject = rest.slice(0, nl);
      const diff = rest.slice(nl + 1);
      const label = `commit ${short(sha)} (${an}, ${date.slice(0, 10)} : ${truncate(subject, 60)})`;
      if (headSet.has(sha)) findings.push(...scanAddedLines(diff, label, ctx, HISTORY_SECRET_RULES, R.HISTORY_SECRET));
      else findings.push(...scanAddedLines(diff, label, ctx, HISTORY_RULES.concat(HISTORY_SECRET_RULES), R.BRANCH_ONLY_CODE));
    }

    // Branches non fusionnées récentes
    const unmerged = [];
    if (defaultBranch) {
      for (const b of branches.filter(x => !protectedBranches.includes(x))) {
        const last = (tryGit(['log', '-1', '--format=%cI%x1f%an', b.ref], root) || '').trim().split('\x1f');
        if (!last[0] || last[0] < since) continue;
        const ahead = Number((tryGit(['rev-list', '--count', `${defaultBranch.ref}..${b.ref}`], root) || '0').trim());
        if (ahead > 0) unmerged.push({ branche: b.name, dernierCommit: last[0].slice(0, 10), auteur: last[1], commitsEnAvance: ahead });
      }
    }

    // Dédoublonnage : un même motif vu via le diff du tag et via le commit n'est signalé qu'une fois
    const seenHist = new Set();
    const dedup = findings.filter(f => {
      if (f.rule !== R.BRANCH_ONLY_CODE.id && f.rule !== R.HISTORY_SECRET.id) return true;
      const k = f.rule + '|' + String(f.file).split(' — ').pop() + '|' + f.line + '|' + f.evidence;
      if (seenHist.has(k)) return false;
      seenHist.add(k); return true;
    });
    findings.length = 0; findings.push(...dedup);

    const snapshot = {
      tags: Object.fromEntries(tags.map(t => [t.name, t.commit])),
      branches: Object.fromEntries(protectedBranches.map(b => [b.name, b.sha])),
    };
    return {
      findings, status: 'ok', notes, filesAnalyzed: recent.length,
      inventory: { git: { periodeJours: days, brancheParDefaut: defaultBranch && defaultBranch.name, branchesProtegees: protectedBranches.map(b => b.name), tagsAnalyses: tagInfos, commitsDirects: directs.slice(0, 50).map(d => ({ branche: d.branche, commit: short(d.sha), sha: d.sha, auteur: d.auteur, date: d.date.slice(0, 10), sujet: truncate(d.sujet, 80) })), modificationsSensibles: sensitiveChanges.slice(0, 60), branchesNonFusionnees: unmerged.slice(0, 50), commitsAnalyses: recent.length } },
      gitSnapshot: snapshot,
      protectedCommits: protCommits.map(c => c.sha),
    };
  },
};

/** Applique des règles aux seules lignes ajoutées d'un diff unifié. */
function scanAddedLines(diff, label, ctx, rules, wrapRule) {
  const out = [];
  let file = null; let n = 0;
  const perFile = new Map();
  for (const line of diff.split('\n')) {
    if (line.startsWith('diff --git')) { file = (/ b\/(.+)$/.exec(line) || [])[1] || null; continue; }
    if (line.startsWith('@@')) { const m = /\+(\d+)/.exec(line); n = m ? Number(m[1]) : 0; continue; }
    if (line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('+') && file) {
      if (!perFile.has(file)) perFile.set(file, []);
      perFile.get(file).push({ n, text: line.slice(1) });
      n++;
    }
  }
  for (const [f, lines] of perFile) {
    if (/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$|\.min\.js$|\.map$/.test(f)) continue;
    for (const hit of scanLines(lines, rules, { file: f, category: G, maxPerRule: 2, projectType: ctx.projectType })) {
      out.push(makeFinding(wrapRule, { file: `${label} — ${f}`, line: hit.line, evidence: `[${hit.title}] ${hit.evidence}`, severity: wrapRule.id === R.HISTORY_SECRET.id ? 'high' : (hit.severity === 'critical' ? 'critical' : 'high') }));
    }
  }
  return out;
}
