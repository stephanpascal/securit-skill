'use strict';
const { scanLines } = require('../lib/patterns');
const { SHELL_RULES } = require('../lib/shell-rules');
const { makeFinding } = require('../lib/finding');
const { maskValue } = require('../lib/util');

const R = {
  ADD_URL: { id: 'DOCKER_ADD_URL', sev: 'high', cat: 'docker', review: true, title: 'ADD depuis une URL distante', desc: 'ADD télécharge un contenu distant sans vérification d\'intégrité au moment du build.', fix: 'Utiliser COPY avec un fichier versionné, ou télécharger avec vérification d\'empreinte (sha256).' },
  TAG_LATEST: { id: 'DOCKER_IMAGE_NON_FIGEE', sev: 'low', cat: 'docker', title: 'Image de base non figée (latest ou sans tag)', desc: 'L\'image de base peut changer à chaque build : un contenu malveillant peut être introduit en amont.', fix: 'Figer la version et idéalement le digest (image:1.2.3@sha256:…).' },
  REGISTRY: { id: 'DOCKER_REGISTRE_NON_AUTORISE', sev: 'medium', cat: 'docker', review: true, title: 'Image provenant d\'un registre non autorisé', desc: 'L\'image de base ne provient pas d\'un registre de la liste autorisée.', fix: 'Utiliser une image issue d\'Artifactory / du registre d\'entreprise.' },
  SECRET: { id: 'DOCKER_SECRET_ENV', sev: 'high', cat: 'docker', title: 'Secret en clair dans ENV/ARG', desc: 'Les valeurs ENV/ARG restent lisibles dans les couches et l\'historique de l\'image.', fix: 'Utiliser les secrets de build (RUN --mount=type=secret) ou des secrets Kubernetes.' },
  NODE_OPTIONS: { id: 'DOCKER_NODE_OPTIONS', sev: 'high', cat: 'docker', review: true, title: 'NODE_OPTIONS chargeant un module (--require / --import)', desc: 'Permet de charger silencieusement du code avant l\'application dans chaque processus Node.', fix: 'Supprimer sauf justification documentée (APM, instrumentation connue).' },
  NPM_CONFIG_ENV: { id: 'DOCKER_NPM_CONFIG', sev: 'medium', cat: 'docker', review: true, title: 'Configuration npm modifiée par variable d\'environnement', desc: 'NPM_CONFIG_REGISTRY / SCRIPT_SHELL / NODE_OPTIONS changent la source des paquets ou le shell d\'exécution des scripts.', fix: 'Vérifier la valeur ; seul le registre d\'entreprise doit être utilisé.' },
  NPM_SCRIPTS: { id: 'DOCKER_NPM_SANS_IGNORE_SCRIPTS', sev: 'medium', cat: 'docker', title: 'Installation npm sans --ignore-scripts', desc: 'Les scripts preinstall/install/postinstall de toutes les dépendances (y compris transitives) sont exécutés pendant le build.', fix: 'Utiliser "npm ci --ignore-scripts" et n\'autoriser explicitement que les paquets nécessitant une compilation.' },
  ROOT: { id: 'DOCKER_UTILISATEUR_ROOT', sev: 'medium', cat: 'docker', title: 'Le conteneur s\'exécute en root', desc: 'Aucune instruction USER non-root dans l\'étape finale : une compromission de l\'application donne les droits root dans le conteneur.', fix: 'Ajouter USER node (ou un utilisateur dédié) dans l\'étape finale.' },
  EXPOSE: { id: 'DOCKER_PORT_INATTENDU', sev: 'medium', cat: 'docker', review: true, title: 'Port exposé inhabituel', desc: 'Un port non standard est exposé : il peut correspondre à un service caché (backdoor, debug).', fix: 'Vérifier quel processus écoute sur ce port et le supprimer s\'il n\'est pas nécessaire.' },
  EXPOSE_SSH: { id: 'DOCKER_PORT_SSH', sev: 'high', cat: 'docker', title: 'Port SSH (22) exposé', desc: 'Exposer SSH dans un conteneur applicatif est une porte d\'entrée.', fix: 'Supprimer EXPOSE 22 et tout serveur SSH.' },
  ENTRY_SCRIPT: { id: 'DOCKER_SCRIPT_DEMARRAGE', sev: 'info', cat: 'docker', review: true, title: 'Script exécuté au démarrage du conteneur', desc: 'Le point d\'entrée exécute un script : il est analysé par le scanner de scripts s\'il est présent dans le dépôt.', fix: 'Relire le script de démarrage.' },
  ENTRY_MISSING: { id: 'DOCKER_SCRIPT_ABSENT_DU_DEPOT', sev: 'medium', cat: 'docker', review: true, title: 'Script de démarrage introuvable dans le dépôt', desc: 'Le script exécuté au démarrage n\'est pas versionné : il est probablement téléchargé ou généré pendant le build.', fix: 'Versionner le script dans le dépôt pour qu\'il soit relu.' },
  COPY_FROM_EXT: { id: 'DOCKER_COPY_IMAGE_EXTERNE', sev: 'medium', cat: 'docker', review: true, title: 'COPY --from depuis une image externe', desc: 'Des fichiers (souvent des binaires) sont copiés depuis une image tierce sans passer par une étape de build relue.', fix: 'Vérifier l\'image source et figer son digest.' },
  NO_DOCKERIGNORE: { id: 'DOCKER_DOCKERIGNORE_ABSENT', sev: 'medium', cat: 'docker', title: 'COPY de tout le dossier sans .dockerignore', desc: 'Sans .dockerignore, .git (historique complet), .env, .npmrc (tokens) ou node_modules locaux sont copiés dans l\'image et peuvent fuiter.', fix: 'Ajouter un .dockerignore excluant au minimum .git, .env*, .npmrc, node_modules.' },
  DOCKERIGNORE_INCOMPLETE: { id: 'DOCKER_DOCKERIGNORE_INCOMPLET', sev: 'low', cat: 'docker', title: '.dockerignore incomplet', desc: 'Des fichiers sensibles courants ne sont pas exclus du contexte de build.', fix: 'Ajouter les entrées manquantes.' },
  NPMRC_COPY: { id: 'DOCKER_COPIE_NPMRC', sev: 'low', cat: 'docker', review: true, title: 'Copie d\'un .npmrc dans l\'image', desc: 'Un .npmrc peut contenir un token ou rediriger le registre ; s\'il reste dans l\'image finale, le token fuit.', fix: 'Utiliser un secret de build et supprimer le .npmrc dans la même couche.' },
};

const SECRET_KEYS = /^(?:[A-Z0-9_]*?)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*$/i;

function logicalLines(text) {
  const raw = text.split(/\r?\n/);
  const out = [];
  let cur = null;
  raw.forEach((l, i) => {
    const t = l.replace(/\s+$/, '');
    if (cur === null) {
      if (/^\s*#/.test(t)) return;
      cur = { n: i + 1, text: t };
    } else if (!/^\s*#/.test(t)) {
      cur.text += ' ' + t.trim();
    }
    if (cur.text.endsWith('\\')) { cur.text = cur.text.slice(0, -1); return; }
    out.push(cur); cur = null;
  });
  if (cur) out.push(cur);
  return out;
}

function parseImage(ref) {
  const noDigest = ref.split('@')[0];
  const digest = ref.includes('@');
  const parts = noDigest.split('/');
  let registry = 'docker.io';
  if (parts.length > 1 && (parts[0].includes('.') || parts[0].includes(':') || parts[0] === 'localhost')) registry = parts[0];
  const last = parts[parts.length - 1];
  const tag = last.includes(':') ? last.split(':').pop() : null;
  return { registry, tag, digest };
}

module.exports = {
  id: 'dockerfile',
  label: 'Dockerfile',
  category: 'docker',
  controls: [
    'Commandes shell dangereuses (curl | sh, reverse shell, base64 exécuté, LD_PRELOAD, persistance cron/systemd, SSH)',
    'ADD depuis une URL, COPY --from image externe',
    'Image de base : version figée, registre autorisé',
    'Secrets en clair dans ENV/ARG, NODE_OPTIONS --require, variables NPM_CONFIG_*',
    'npm/yarn install sans --ignore-scripts, changement de registre',
    'Utilisateur root, ports exposés inhabituels ou SSH',
    '.dockerignore absent ou incomplet alors que tout le dossier est copié (.git, .env, .npmrc embarqués)',
    'Scripts de démarrage (ENTRYPOINT/CMD) présents ou non dans le dépôt',
    'Domaines suspects, IP publiques, mineurs de cryptomonnaie',
  ],
  async run(ctx) {
    const findings = [];
    const files = ctx.files.filter(f => /^(dockerfile|containerfile)([._-].*)?$/i.test(f.base) || /\.dockerfile$/i.test(f.base));
    const images = [];
    const ports = [];
    for (const file of files) {
      const text = ctx.readText(file);
      if (!text) continue;
      const lines = logicalLines(text);
      findings.push(...scanLines(lines, SHELL_RULES, { file: file.rel, category: 'docker', projectType: ctx.projectType }));
      const stageNames = new Set();
      let stageUser = null;
      let stageIndex = -1;
      for (const { n, text: l } of lines) {
        const m = /^\s*([A-Za-z]+)\s+(.*)$/.exec(l);
        if (!m) continue;
        const instr = m[1].toUpperCase();
        const args = m[2].trim();
        const at = (rule, data) => findings.push(makeFinding(rule, Object.assign({ file: file.rel, line: n, evidence: l }, data)));
        if (instr === 'FROM') {
          stageIndex++; stageUser = null;
          const fm = /^(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?/i.exec(args);
          if (!fm) continue;
          const img = fm[1];
          if (fm[2]) stageNames.add(fm[2].toLowerCase());
          if (img === 'scratch' || stageNames.has(img.toLowerCase()) || img.includes('$')) continue;
          const info = parseImage(img);
          images.push({ image: img, fichier: file.rel, ligne: n });
          if (!info.digest && (!info.tag || info.tag === 'latest')) at(R.TAG_LATEST);
          const allowed = ctx.config.docker.registresAutorises || [];
          if (allowed.length && !allowed.some(a => info.registry === a || img.startsWith(a))) at(R.REGISTRY, { description: `${R.REGISTRY.desc} Registre : ${info.registry}.` });
        } else if (instr === 'ADD' && /https?:\/\//i.test(args)) {
          at(R.ADD_URL);
        } else if (instr === 'ENV' || instr === 'ARG') {
          const pairs = args.match(/([A-Za-z_][A-Za-z0-9_]*)(?:=|\s+)("[^"]*"|'[^']*'|\S+)?/g) || [];
          for (const p of pairs) {
            const [k, ...rest] = p.split(/=|\s+/);
            const v = rest.join('=').replace(/^["']|["']$/g, '');
            if (SECRET_KEYS.test(k) && v && !v.startsWith('$') && v.length >= 4) at(R.SECRET, { evidence: `${instr} ${k}=${maskValue(v)}` });
            if (/^NODE_OPTIONS$/i.test(k) && /(--require|-r\s|--import|--loader|--experimental-loader)/.test(v + ' ' + args)) at(R.NODE_OPTIONS);
            if (/^NPM_CONFIG_(REGISTRY|SCRIPT_SHELL|NODE_OPTIONS|IGNORE_SCRIPTS|STRICT_SSL)$/i.test(k)) at(R.NPM_CONFIG_ENV);
          }
        } else if (instr === 'RUN') {
          if (/\b(npm\s+(install|i|ci|add)|yarn(\s+install)?(\s|$)|pnpm\s+(install|i|add))\b/.test(args) && !/--ignore-scripts|ignore-scripts\s*=?\s*true/.test(args)) at(R.NPM_SCRIPTS);
        } else if (instr === 'USER') {
          stageUser = args.split(/\s/)[0];
        } else if (instr === 'EXPOSE') {
          for (const p of args.split(/\s+/)) {
            const port = parseInt(p, 10);
            if (!port) continue;
            ports.push({ port, source: 'Dockerfile', fichier: file.rel, ligne: n });
            if (port === 22) at(R.EXPOSE_SSH);
            else if (!ctx.config.ports.attendus.includes(port)) at(R.EXPOSE, { description: `${R.EXPOSE.desc} Port : ${port}.` });
          }
        } else if (instr === 'ENTRYPOINT' || instr === 'CMD') {
          const sm = /([\w./-]+\.(sh|bash|ps1|py|pl))\b/.exec(args);
          if (sm) {
            const scriptBase = sm[1].split('/').pop();
            const inRepo = ctx.files.some(f => f.base === scriptBase);
            at(inRepo ? R.ENTRY_SCRIPT : R.ENTRY_MISSING, { description: `${(inRepo ? R.ENTRY_SCRIPT : R.ENTRY_MISSING).desc} Script : ${sm[1]}.` });
          }
        } else if (instr === 'COPY') {
          const cm = /--from=(\S+)/.exec(args);
          if (cm && !stageNames.has(cm[1].toLowerCase()) && !/^\d+$/.test(cm[1])) at(R.COPY_FROM_EXT);
          if (/\.npmrc\b/.test(args)) at(R.NPMRC_COPY);
        }
      }
      if (stageIndex >= 0 && (!stageUser || /^(root|0)(:|$)/.test(stageUser))) {
        findings.push(makeFinding(R.ROOT, { file: file.rel, evidence: stageUser ? `USER ${stageUser}` : 'Aucune instruction USER dans l\'étape finale' }));
      }
      // .dockerignore : un "COPY . ." sans exclusions embarque .git, .env, .npmrc… dans l'image
      const copyAll = lines.find(l => /^\s*(COPY|ADD)\s+(--[\w=-]+\s+)*\.\/?\s+\S+/i.test(l.text));
      if (copyAll) {
        const dir = file.rel.includes('/') ? file.rel.slice(0, file.rel.lastIndexOf('/') + 1) : '';
        const ign = ctx.files.find(f => f.rel === dir + '.dockerignore' || f.rel === file.rel + '.dockerignore' || f.rel === '.dockerignore');
        if (!ign) findings.push(makeFinding(R.NO_DOCKERIGNORE, { file: file.rel, line: copyAll.n, evidence: copyAll.text.trim() }));
        else {
          const txt = ctx.readText(ign) || '';
          const missing = ['.git', '.env', '.npmrc', 'node_modules'].filter(p => !new RegExp('^\\s*(\\*\\*/)?' + p.replace('.', '\\.') + '\\b', 'm').test(txt) && !/^\s*\*\s*$/m.test(txt));
          if (missing.length) findings.push(makeFinding(R.DOCKERIGNORE_INCOMPLETE, { file: ign.rel, evidence: 'Non exclus : ' + missing.join(', ') }));
        }
      }
    }
    return { findings, filesAnalyzed: files.length, inventory: { images, ports }, notes: files.length ? [] : ['Aucun Dockerfile trouvé.'] };
  },
};
