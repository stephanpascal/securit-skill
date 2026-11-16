'use strict';
const { makeFinding } = require('../lib/finding');

const S = 'structure';
const R = {
  NODE_MODULES: { id: 'STRUCT_NODE_MODULES_VERSIONNE', sev: 'high', title: 'node_modules versionné dans le dépôt', desc: 'Du code tiers non audité (et potentiellement modifié) est versionné ; il échappe au lockfile.', fix: 'Supprimer node_modules du dépôt et l\'ajouter au .gitignore.' },
  BUILD: { id: 'STRUCT_ARTEFACTS_BUILD', sev: 'medium', review: true, title: 'Artefacts de build versionnés (dist, build, .angular)', desc: 'Du code généré peut différer des sources : une modification malveillante y passe inaperçue.', fix: 'Ne pas versionner les artefacts ; les produire en CI.' },
  BINARY: { id: 'STRUCT_BINAIRE_EXECUTABLE', sev: 'high', review: true, title: 'Binaire exécutable versionné', desc: 'Un exécutable (.exe, .dll, .so, ELF…) ne peut pas être relu et peut contenir n\'importe quoi.', fix: 'Supprimer ou justifier son origine (empreinte, source officielle).' },
  ARCHIVE: { id: 'STRUCT_ARCHIVE', sev: 'medium', review: true, title: 'Archive versionnée', desc: 'Le contenu d\'une archive n\'est pas visible lors des relectures de merge request.', fix: 'Versionner le contenu décompressé ou justifier.' },
  SCRIPT_IN_ASSETS: { id: 'STRUCT_SCRIPT_DANS_SOURCES', sev: 'high', review: true, title: 'Script système placé dans les sources ou les assets', desc: 'Un script shell / PowerShell / Python dans src/ ou assets/ est inhabituel et peut être embarqué dans l\'image ou servi publiquement.', fix: 'Vérifier le rôle de ce fichier.' },
  CODE_IN_ASSETS: { id: 'STRUCT_CODE_DANS_ASSETS', sev: 'medium', review: true, title: 'Fichier de code dans le dossier assets', desc: 'Les assets sont copiés tels quels sans passer par la compilation ni le lint : emplacement discret pour un script.', fix: 'Vérifier ce fichier.' },
  DOUBLE_EXT: { id: 'STRUCT_DOUBLE_EXTENSION', sev: 'high', review: true, title: 'Fichier à double extension', desc: 'Un fichier « image.png.js » se fait passer pour un autre type.', fix: 'Vérifier le contenu réel.' },
  FAKE_IMAGE: { id: 'STRUCT_FAUSSE_IMAGE', sev: 'high', review: true, title: 'Fichier image contenant du texte ou du code', desc: 'Une « image » qui est en réalité du texte peut cacher un script (technique de dissimulation).', fix: 'Ouvrir le fichier et vérifier son contenu.' },
  K8S_MISPLACED: { id: 'STRUCT_MANIFESTE_K8S_HORS_PLACE', sev: 'medium', review: true, title: 'Manifeste Kubernetes / chart Helm dans un projet applicatif', desc: 'Un projet fe/bff ne contient normalement pas de manifestes de déploiement : ils pourraient être utilisés par une autre chaîne ou surcharger la configuration.', fix: 'Vérifier pourquoi ce fichier est présent.' },
  SERVER_MISPLACED: { id: 'STRUCT_CONFIG_SERVEUR_HORS_PLACE', sev: 'medium', review: true, title: 'Configuration serveur dans un emplacement inhabituel', desc: 'Une configuration nginx/apache cachée dans src/ ou assets/ peut être copiée à la place de la configuration attendue.', fix: 'Vérifier son utilisation.' },
  APP_IN_HELM: { id: 'STRUCT_CODE_DANS_HELM', sev: 'medium', review: true, title: 'Code applicatif dans un projet de déploiement Helm', desc: 'Un chart Helm ne contient normalement que des templates et des valeurs.', fix: 'Vérifier le rôle de ce fichier.' },
  HIDDEN: { id: 'STRUCT_FICHIER_CACHE_INHABITUEL', sev: 'low', review: true, title: 'Fichier ou dossier caché inhabituel', desc: 'Fichier commençant par un point, hors de la liste des fichiers de configuration courants.', fix: 'Vérifier son rôle.' },
  SYMLINK: { id: 'STRUCT_LIEN_SYMBOLIQUE', sev: 'medium', review: true, title: 'Lien symbolique versionné', desc: 'Un lien symbolique peut pointer hors du dépôt (ex. vers un fichier système lors du build).', fix: 'Vérifier la cible du lien.' },
  LARGE: { id: 'STRUCT_FICHIER_TROP_GROS', sev: 'info', title: 'Fichier trop volumineux pour l\'analyse de contenu', desc: 'Ce fichier dépasse la taille maximale analysée.', fix: 'Vérifier manuellement si nécessaire.' },
  SUBMODULE: { id: 'STRUCT_SOUS_MODULE', sev: 'medium', review: true, title: 'Sous-module git (non cloné, non analysé)', desc: 'Le code d\'un sous-module provient d\'un autre dépôt et n\'est pas couvert par cette analyse.', fix: 'Analyser également le dépôt du sous-module.' },
  SUBMODULE_EXT: { id: 'STRUCT_SOUS_MODULE_EXTERNE', sev: 'high', review: true, title: 'Sous-module git hors de l\'instance GitLab', desc: 'Du code provient d\'un dépôt externe.', fix: 'Vérifier la source.' },
  IOC: { id: 'STRUCT_FICHIER_IOC', sev: 'critical', title: 'Fichier portant le nom d\'un indicateur de compromission connu', desc: 'Nom de fichier caractéristique d\'une campagne malveillante (ex. workflow « shai-hulud », dépôt « s1ngularity »), voir rules/ioc.json.', fix: 'Considérer le dépôt comme compromis : examiner l\'historique du fichier et révoquer les secrets.' },
};
for (const r of Object.values(R)) r.cat = S;

const KNOWN_HIDDEN = new Set(['.gitignore', '.gitattributes', '.gitmodules', '.gitkeep', '.editorconfig', '.npmrc', '.nvmrc', '.node-version', '.browserslistrc', '.dockerignore', '.gitlab-ci.yml', '.gitlab', '.vscode', '.idea', '.husky', '.github', '.helmignore', '.env.example', '.env.sample', '.env.template', '.prettierrc', '.prettierignore', '.eslintrc', '.eslintignore', '.stylelintrc', '.stylelintignore', '.babelrc', '.mocharc', '.nycrc', '.jshintrc', '.yarnrc', '.yarnrc.yml', '.yarn', '.commitlintrc', '.lintstagedrc', '.releaserc', '.sonarcloud.properties', '.hadolint.yaml', '.trivyignore', '.gitleaks.toml', '.angular', '.storybook', '.devcontainer', '.htaccess', '.pre-commit-config.yaml', '.tool-versions', '.swcrc', '.czrc', '.npmignore', '.versionrc', '.markdownlint.json', '.secrets.baseline', '.terraform', '.ci', '.config', '.changeset', '.mailmap', '.ncurc', '.snyk', '.renovaterc', 'renovate.json']);
const BIN_EXT = /\.(exe|dll|so|dylib|bin|elf|msi|scr|com|cpl|jar|war|class|pyc|node|o|a)$/i;
const ARCH_EXT = /\.(zip|tgz|tar|gz|bz2|xz|7z|rar|jar)$/i;
const SCRIPT_EXT = /\.(sh|bash|ps1|psm1|bat|cmd|vbs|py|pl|rb|php)$/i;
const IMG_EXT = /\.(png|jpe?g|gif|ico|bmp|webp|woff2?|ttf|otf|eot)$/i;
const IOC_FILES = (require('../rules/ioc.json').fichiers || []).map(s => s.toLowerCase());

module.exports = {
  id: 'structure',
  label: 'Structure du dépôt',
  category: S,
  controls: [
    'node_modules, artefacts de build, binaires exécutables, archives, liens symboliques versionnés',
    'Scripts système ou code dans src/ et assets/, doubles extensions, fausses images et fausses polices (fichier texte/JS déguisé)',
    'Noms de fichiers d\'indicateurs de compromission connus (rules/ioc.json)',
    'Fichiers hors de leur place : manifestes Kubernetes/Helm ou configs serveur dans un fe/bff, code applicatif dans un chart Helm',
    'Fichiers cachés inhabituels, sous-modules git (non clonés)',
  ],
  async run(ctx) {
    const findings = [];
    const t = ctx.projectType;
    const at = (rule, file, data) => findings.push(makeFinding(rule, Object.assign({ file, evidence: file }, data)));
    for (const d of ctx.skippedDirs) {
      const base = d.split('/').pop();
      if (base === 'node_modules') at(R.NODE_MODULES, d);
      else if (base === '.angular') at(R.BUILD, d);
    }
    for (const s of ctx.symlinks) at(R.SYMLINK, s);
    const buildDirs = new Set();
    const appInHelm = new Map();
    for (const f of ctx.files) {
      const rel = f.rel;
      const parts = rel.split('/');
      if (/^(dist|build|out|www)\//.test(rel) && !buildDirs.has(parts[0])) { buildDirs.add(parts[0]); at(R.BUILD, parts[0] + '/'); }
      if (f.tooLarge) at(R.LARGE, rel, { evidence: `${rel} (${Math.round(f.size / 1024)} Ko)` });
      if (IOC_FILES.some(n => rel.toLowerCase().includes(n))) at(R.IOC, rel);
      if (BIN_EXT.test(f.base)) at(R.BINARY, rel);
      else if (ARCH_EXT.test(f.base) && !/(^|\/)charts\/[^/]+\.tgz$/.test(rel)) at(R.ARCHIVE, rel);
      else if (ARCH_EXT.test(f.base)) at(R.ARCHIVE, rel, { severity: 'low', description: 'Sous-chart Helm vendorisé : son contenu est décompressé et analysé par le scanner Helm.' });
      if (/\.(png|jpe?g|gif|pdf|txt|docx?|xlsx?|csv)\.(js|ts|sh|exe|bat|ps1|cmd|vbs|scr|html?)$/i.test(f.base)) at(R.DOUBLE_EXT, rel);
      if (IMG_EXT.test(f.base) && f.size > 0 && f.size < 2 * 1024 * 1024) {
        const txt = ctx.readText(f);
        if (txt !== null && !/^\s*<svg/i.test(txt)) at(R.FAKE_IMAGE, rel, { evidence: `${rel} : ${txt.slice(0, 80).replace(/\s+/g, ' ')}` });
      }
      if (/(^|\/)src\//.test(rel) && SCRIPT_EXT.test(f.base)) at(R.SCRIPT_IN_ASSETS, rel, { severity: t === 'fe' ? 'high' : 'medium' });
      else if (/(^|\/)(assets|public|static)\//.test(rel) && SCRIPT_EXT.test(f.base)) at(R.SCRIPT_IN_ASSETS, rel);
      if (/(^|\/)(src\/)?assets\//.test(rel) && /\.(js|mjs|cjs|wasm)$/i.test(f.base)) at(R.CODE_IN_ASSETS, rel);
      if ((t === 'fe' || t === 'bff')) {
        if (/(^|\/)(Chart\.ya?ml|values\.ya?ml)$/.test(rel) || (/\.(ya?ml)$/.test(f.base) && /(^|\/)(templates|k8s|kubernetes|manifests|helm)\//.test(rel))) at(R.K8S_MISPLACED, rel);
        else if (/\.ya?ml$/.test(f.base) && !/(^|\/)\.gitlab|gitlab-ci|docker-compose|compose\.|\.github\/|openapi|swagger|lefthook|pnpm-lock|\.pre-commit|sonar|renovate|dependabot|codecov|mkdocs/.test(rel)) {
          const txt = ctx.readText(f) || '';
          if (/^kind:\s*(Deployment|Pod|Job|CronJob|DaemonSet|ConfigMap|Secret|Service|Ingress|Role|ClusterRole\w*|RoleBinding)\s*$/m.test(txt)) at(R.K8S_MISPLACED, rel);
        }
        if (/(^|\/)(src|assets|public)\//.test(rel) && (/\.conf$/.test(f.base) || f.base === '.htaccess')) at(R.SERVER_MISPLACED, rel);
      }
      if (t === 'helm' && /\.(js|mjs|cjs|ts|py|go|java|php|rb)$/i.test(f.base)) {
        const dir = parts.length > 1 ? parts[0] + '/' : '(racine)';
        if (!appInHelm.has(dir)) appInHelm.set(dir, []);
        appInHelm.get(dir).push(rel);
      }
      const hiddenPart = parts.find(p => p.startsWith('.') && p !== '.' && p !== '..');
      if (hiddenPart && !KNOWN_HIDDEN.has(hiddenPart) && !/^\.(env|prettierrc|eslintrc|stylelintrc|babelrc|mocharc|lintstagedrc|commitlintrc|releaserc|swcrc)(\.|$)/.test(hiddenPart) && !/^\.gitlab/.test(hiddenPart)) {
        if (parts.indexOf(hiddenPart) === parts.length - 1 || !findings.some(x => x.rule === R.HIDDEN.id && x.file && x.file.startsWith(parts.slice(0, parts.indexOf(hiddenPart) + 1).join('/')))) {
          at(R.HIDDEN, parts.slice(0, parts.indexOf(hiddenPart) + 1).join('/'));
        }
      }
    }
    // Code applicatif dans un chart : un constat par dossier de premier niveau
    for (const [dir, list] of appInHelm) {
      at(R.APP_IN_HELM, dir, { evidence: `${list.length} fichier(s) : ${list.slice(0, 5).join(', ')}${list.length > 5 ? '…' : ''}` });
    }
    // Sous-modules
    const gm = ctx.files.find(f => f.rel === '.gitmodules');
    if (gm) {
      const txt = ctx.readText(gm) || '';
      const gitlabHost = ctx.gitlabHost;
      for (const m of txt.matchAll(/url\s*=\s*(\S+)/g)) {
        const external = gitlabHost && !m[1].includes(gitlabHost) && !m[1].startsWith('../') && !m[1].startsWith('./');
        at(external ? R.SUBMODULE_EXT : R.SUBMODULE, '.gitmodules', { evidence: m[1] });
      }
    }
    return { findings, filesAnalyzed: ctx.files.length, notes: [] };
  },
};
