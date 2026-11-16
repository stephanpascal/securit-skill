'use strict';
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { scanText } = require('../lib/patterns');
const { SHELL_RULES } = require('../lib/shell-rules');
const { makeFinding } = require('../lib/finding');
const { extractTgz } = require('../lib/tar');
const serverConfig = require('./server-config');
const sourceCode = require('./source-code');

const K = 'k8s';

function prevKey(lines, idx) {
  const ind = lines[idx].search(/\S/);
  for (let i = idx - 1; i >= 0; i--) {
    const l = lines[i];
    if (!l.trim()) continue;
    const li = l.search(/\S/);
    if (li < ind || (li === ind && !/^\s*-/.test(l))) return l.trim();
  }
  return '';
}

const RULES = [
  { id: 'K8S_PRIVILEGIE', sev: 'critical', re: /^\s*privileged:\s*true\b/, title: 'Conteneur privilégié', desc: 'Un conteneur privilégié a un accès quasi total au nœud : évasion triviale.', fix: 'Supprimer privileged: true.' },
  { id: 'K8S_ESPACE_NOMS_HOTE', sev: 'high', re: /^\s*host(Network|PID|IPC):\s*true\b/, title: 'Partage des espaces de noms de l\'hôte (hostNetwork/PID/IPC)', desc: 'Le pod voit le réseau ou les processus du nœud.', fix: 'Supprimer sauf composant système justifié.' },
  { id: 'K8S_HOSTPATH', sev: 'high', review: true, re: /^\s*hostPath:/, title: 'Montage d\'un dossier du nœud (hostPath)', desc: 'Le pod accède au système de fichiers du nœud.', fix: 'Utiliser emptyDir, configMap ou un volume persistant.' },
  { id: 'K8S_HOSTPATH_SENSIBLE', sev: 'critical', re: /^\s*path:\s*["']?(\/|\/var\/run\/docker\.sock|\/run\/containerd[\w/.]*|\/var\/run\/crio[\w/.]*|\/etc|\/root|\/proc|\/sys|\/var\/lib\/kubelet|\/home|\/var\/log)["']?\s*$/, filter: (l, m, o) => /hostPath/.test(o._prev || ''), title: 'Montage d\'un chemin sensible du nœud', desc: 'Accès au socket du moteur de conteneurs, à /etc, /root, /proc… : prise de contrôle du nœud.', fix: 'Supprimer.' },
  { id: 'K8S_CAPACITES', sev: 'high', re: /^\s*-\s*["']?(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL|NET_RAW|SYS_MODULE|DAC_READ_SEARCH|SYS_RAWIO|BPF)["']?\s*$|add:\s*\[[^\]]*(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|ALL|SYS_MODULE)/, filter: (l, m, o) => /add:\s*\[/.test(l) || /^add:/.test(o._prev || ''), title: 'Capacités Linux dangereuses ajoutées', desc: 'SYS_ADMIN, NET_ADMIN, SYS_PTRACE… donnent des privilèges proches de root sur le nœud.', fix: 'Retirer ; utiliser drop: [ALL].' },
  { id: 'K8S_EXECUTION_ROOT', sev: 'medium', re: /runAsUser:\s*0\b|runAsNonRoot:\s*false|allowPrivilegeEscalation:\s*true/, title: 'Exécution en root ou élévation de privilèges autorisée', desc: 'Le conteneur peut s\'exécuter en root ou élever ses privilèges.', fix: 'runAsNonRoot: true, allowPrivilegeEscalation: false.' },
  { id: 'K8S_HOOK_HELM', sev: 'high', review: true, re: /["']?helm\.sh\/hook["']?\s*:\s*["']?[\w\-, ]*(pre|post)-(install|upgrade|delete|rollback)/, title: 'Hook Helm : ressource exécutée automatiquement au déploiement', desc: 'Un Job/Pod hook s\'exécute à chaque install/upgrade, souvent avec des droits élevés : emplacement discret pour une action malveillante.', fix: 'Relire la commande du hook et son image.' },
  { id: 'K8S_LIFECYCLE', sev: 'medium', review: true, re: /^\s*(postStart|preStop):/, title: 'Commande exécutée au démarrage/arrêt du conteneur (lifecycle)', desc: 'postStart/preStop exécutent une commande en dehors du processus principal.', fix: 'Vérifier la commande.' },
  { id: 'K8S_INIT_CONTAINER', sev: 'low', review: true, re: /^\s*initContainers:/, title: 'Conteneurs d\'initialisation', desc: 'Les initContainers s\'exécutent avant l\'application (souvent avec un accès aux volumes partagés).', fix: 'Vérifier leurs images et commandes.' },
  { id: 'K8S_SHELL_C', sev: 'medium', review: true, re: /(command|args):\s*\[?\s*["']?(\/bin\/|\/usr\/bin\/)?(ba)?sh["']?\s*,\s*["']-c|^\s*-\s*["']?-c["']?\s*$/, title: 'Commande shell inline (sh -c)', desc: 'Une commande shell libre est exécutée dans le conteneur.', fix: 'Relire la commande.' },
  { id: 'K8S_RBAC_JOKER', sev: 'critical', re: /^\s*(verbs|resources|apiGroups):\s*\[\s*["']\*["']\s*\]|^\s*-\s*["']\*["']\s*$/, title: 'RBAC avec joker (*)', desc: 'Droits illimités sur l\'API Kubernetes.', fix: 'Lister explicitement les ressources et verbes nécessaires.' },
  { id: 'K8S_CLUSTER_ADMIN', sev: 'high', review: true, re: /^\s*name:\s*["']?cluster-admin["']?\s*$/, title: 'Référence au rôle cluster-admin', desc: 'Un compte de service lié à cluster-admin contrôle tout le cluster.', fix: 'Utiliser un rôle restreint au namespace.' },
  { id: 'K8S_LECTURE_SECRETS', sev: 'high', review: true, re: /resources:\s*\[[^\]]*["']?secrets["']?|^\s*-\s*["']?secrets["']?\s*$/, title: 'Droit de lecture des secrets Kubernetes', desc: 'L\'application peut lire les secrets du namespace (tokens, mots de passe d\'autres applications).', fix: 'Retirer sauf nécessité.' },
  { id: 'K8S_RESSOURCE_SENSIBLE', sev: 'medium', review: true, re: /^kind:\s*(ClusterRole|ClusterRoleBinding|MutatingWebhookConfiguration|ValidatingWebhookConfiguration|DaemonSet|CronJob|PodSecurityPolicy|CustomResourceDefinition|PriorityClass)\s*$/, filter: (l) => ({ severity: /Webhook|ClusterRole/.test(l) ? 'high' : 'medium' }), title: 'Ressource Kubernetes inhabituelle pour une application', desc: 'Webhook (peut modifier tous les pods créés), ClusterRole, DaemonSet (sur chaque nœud), CronJob (exécution planifiée)…', fix: 'Vérifier que cette ressource est attendue dans le chart applicatif.' },
  { id: 'K8S_EXPOSITION_SERVICE', sev: 'medium', review: true, re: /^\s*type:\s*["']?(NodePort|LoadBalancer)["']?\s*$/, title: 'Service exposé hors du cluster (NodePort / LoadBalancer)', desc: 'Le service est accessible directement depuis l\'extérieur du cluster, sans passer par l\'Ingress.', fix: 'Utiliser ClusterIP + Ingress.' },
  { id: 'K8S_IP_EXTERNE_PORT_HOTE', sev: 'high', re: /^\s*externalIPs:|^\s*hostPort:\s*\d+/, title: 'externalIPs ou hostPort', desc: 'Ouverture d\'un port directement sur le nœud ou capture de trafic par IP externe.', fix: 'Supprimer.' },
  { id: 'K8S_TOKEN_SA', sev: 'low', re: /automountServiceAccountToken:\s*true/, title: 'Montage explicite du token du compte de service', desc: 'Le token API Kubernetes est disponible dans le conteneur.', fix: 'automountServiceAccountToken: false si l\'application n\'appelle pas l\'API.' },
  { id: 'K8S_HELM_LOOKUP', sev: 'high', review: true, re: /\{\{-?\s*(\$\w+\s*:=\s*)?\(?\s*lookup\b/, title: 'Fonction Helm lookup (lecture du cluster au déploiement)', desc: 'Le chart lit des ressources existantes du cluster (ex. secrets) au moment du déploiement.', fix: 'Vérifier quelles ressources sont lues et ce qui en est fait.' },
  { id: 'K8S_HELM_FILES', sev: 'info', review: true, re: /\.Files\.(Get|Glob|AsConfig|AsSecrets)\b/, title: 'Fichiers embarqués par le chart (.Files)', desc: 'Des fichiers du chart sont injectés dans les manifestes (souvent des configurations nginx/scripts).', fix: 'Ces fichiers sont analysés ; vérifier qu\'ils sont attendus.' },
  { id: 'K8S_NAMESPACE_SYSTEME', sev: 'high', review: true, re: /namespace:\s*["']?(kube-system|kube-public|default)["']?\s*$/, filter: l => ({ severity: /default/.test(l) ? 'low' : 'high' }), title: 'Déploiement dans un namespace système', desc: 'Une application n\'a pas à déployer dans kube-system.', fix: 'Utiliser le namespace de l\'application.' },
  { id: 'K8S_HOST_ALIASES', sev: 'medium', review: true, re: /^\s*hostAliases:|dnsPolicy:\s*["']?None|^\s*nameservers:/, title: 'Redirection DNS (hostAliases / dnsConfig)', desc: 'Les résolutions DNS du pod sont forcées : peut rediriger des appels légitimes vers un hôte malveillant.', fix: 'Vérifier les entrées.' },
  { id: 'K8S_SECRET_VERSIONNE', sev: 'medium', review: true, re: /^kind:\s*Secret\s*$/, title: 'Manifeste Secret versionné', desc: 'Les valeurs base64 d\'un Secret versionné sont lisibles par toute personne ayant accès au dépôt.', fix: 'Utiliser un gestionnaire de secrets (Vault, Sealed Secrets, External Secrets).' },
  { id: 'K8S_PROXY_ENV', sev: 'medium', review: true, re: /name:\s*["']?(HTTPS?_PROXY|https?_proxy|ALL_PROXY)["']?/, title: 'Proxy sortant forcé par variable d\'environnement', desc: 'Tout le trafic HTTP sortant de l\'application passe par ce proxy (peut être intercepté).', fix: 'Vérifier que le proxy est celui de l\'entreprise.' },
  { id: 'K8S_NODE_OPTIONS', sev: 'high', review: true, re: /NODE_OPTIONS["']?\s*[\s\S]{0,20}(--require|--import|--loader|-r\s)/, title: 'NODE_OPTIONS chargeant un module', desc: 'Code chargé silencieusement avant l\'application.', fix: 'Supprimer sauf instrumentation documentée.' },
  { id: 'K8S_INGRESS_SNIPPET', sev: 'high', review: true, re: /nginx\.ingress\.kubernetes\.io\/(server-snippet|configuration-snippet|auth-snippet|modsecurity-snippet|stream-snippet)/, title: 'Snippet nginx injecté via annotation Ingress', desc: 'Les snippets permettent d\'injecter une configuration nginx arbitraire dans le contrôleur Ingress partagé (vecteur de vulnérabilités critiques connues).', fix: 'Supprimer ou relire intégralement le snippet.' },
  { id: 'K8S_INGRESS_REDIRECTION', sev: 'medium', review: true, re: /nginx\.ingress\.kubernetes\.io\/(permanent-redirect|temporal-redirect|upstream-vhost|auth-url|proxy-redirect-to|from-to-www-redirect)/, title: 'Redirection ou authentification externe via annotation Ingress', desc: 'Le trafic peut être redirigé ou les en-têtes envoyés vers un autre hôte.', fix: 'Vérifier la cible.' },
  { id: 'K8S_IMAGE_NON_FIGEE', sev: 'low', re: /^\s*-?\s*image:\s*["']?([^\s"'#{}]+)["']?\s*$/, filter: (l, m) => { const img = m[1]; const last = img.split('/').pop(); return !img.includes('@') && (!last.includes(':') || /:latest$/.test(img)); }, title: 'Image non figée (latest ou sans tag)', desc: 'L\'image déployée peut changer sans modification du chart.', fix: 'Figer le tag (et idéalement le digest).' },
].map(r => Object.assign({ cat: K }, r));

const CI_RULES = [
  { id: 'CI_INCLUDE_DISTANT', sev: 'high', review: true, re: /^\s*-?\s*remote:\s*["']?https?:\/\//, title: 'Inclusion d\'une configuration CI distante', desc: 'La CI exécute un fichier distant modifiable par un tiers.', fix: 'Inclure depuis un projet interne avec une ref figée.' },
  { id: 'CI_INCLUDE_PROJET', sev: 'low', review: true, re: /^\s*-?\s*project:\s*["']?\S+/, title: 'Inclusion d\'une configuration CI d\'un autre projet', desc: 'Le pipeline dépend d\'un autre projet : sa modification change ce pipeline.', fix: 'Figer la ref (tag) de l\'inclusion.' },
  { id: 'CI_PUSH_DEPUIS_PIPELINE', sev: 'medium', review: true, re: /\bgit\s+push\b|\bgit\s+tag\s+(-a\s+)?\S+/, title: 'Le pipeline pousse du code ou crée des tags', desc: 'Un pipeline qui pousse/tag peut contourner les protections de branche (le token CI agit au nom d\'un utilisateur).', fix: 'Vérifier les branches visées et les droits du token utilisé.' },
].map(r => Object.assign({ cat: K }, r));

function isYaml(f) { return /\.(ya?ml|tpl)$/i.test(f.base) && !/(^|\/)(pnpm-lock\.yaml|yarn\.lock)$/.test(f.rel); }
function looksK8s(text, rel) { return /^\s*(apiVersion|kind):/m.test(text) || /(^|\/)(templates|charts)\//.test(rel) || /(^|\/)values[\w.-]*\.ya?ml$/.test(rel) || /(^|\/)Chart\.ya?ml$/.test(rel); }

function scanK8sText(text, file, ctx) {
  const lines = text.split(/\r?\n/);
  const out = [];
  lines.forEach((l, i) => {
    if (!l.trim() || /^\s*#/.test(l)) return;
    for (const rule of RULES) {
      const m = rule.re.exec(l);
      if (!m) continue;
      let ov = {};
      if (rule.filter) { const r = rule.filter(l, m, { _prev: prevKey(lines, i) }); if (!r) continue; if (typeof r === 'object') ov = r; }
      out.push(makeFinding(rule, Object.assign({ file, line: i + 1, evidence: l.trim() }, ov)));
    }
  });
  return out;
}

/** Extrait les blocs YAML multi-lignes (clé: | ou >) pour analyser les configurations embarquées dans les ConfigMaps. */
function extractBlocks(text) {
  const lines = text.split(/\r?\n/);
  const blocks = [];
  for (let i = 0; i < lines.length; i++) {
    const m = /^(\s*)["']?([^"':#]+?)["']?:\s*[|>][-+]?\d*\s*$/.exec(lines[i]);
    if (!m) continue;
    const ind = m[1].length;
    const body = [];
    let j = i + 1;
    for (; j < lines.length; j++) {
      const l = lines[j];
      if (l.trim() && l.search(/\S/) <= ind) break;
      body.push(l);
    }
    blocks.push({ key: m[2].trim(), startLine: i + 1, text: body.join('\n') });
    i = j - 1;
  }
  return blocks;
}

function analyzeBlocks(text, file, ctx) {
  const out = [];
  const ports = [];
  for (const b of extractBlocks(text)) {
    if (b.text.length < 20) continue;
    const kind = /\.conf$/.test(b.key) ? serverConfig.kindOf(b.text, '') || 'nginx' : serverConfig.kindOf(b.text, '');
    const label = `${file} [clé ${b.key}]`;
    if (kind === 'nginx' || kind === 'apache') {
      const r = kind === 'nginx' ? serverConfig.analyzeNginx(b.text, label, ctx, b.startLine) : serverConfig.analyzeApache(b.text, label, ctx, b.startLine);
      out.push(...r.findings.map(f => Object.assign(f, { category: K })));
      ports.push(...r.ports);
    } else if (kind === 'supervisor') {
      out.push(...serverConfig.analyzeSupervisor(b.text, label, b.startLine).map(f => Object.assign(f, { category: K })));
    } else if (/\.(m|c)?js$/.test(b.key) || /\brequire\s*\(|module\.exports|=>\s*\{/.test(b.text)) {
      out.push(...scanText(b.text, sourceCode.RULES, { file: label, category: K, lineOffset: b.startLine }));
    }
  }
  return { findings: out, ports };
}

function renderHelm(ctx, chartDir) {
  const helm = ctx.tools.helm;
  if (!helm) return null;
  try {
    return execFileSync(helm, ['template', 'audit', chartDir], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 120000, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
  } catch { return null; }
}

module.exports = {
  id: 'k8s-helm',
  label: 'Helm / Kubernetes / CI (YAML)',
  category: K,
  controls: [
    'Hooks Helm (pre/post-install, upgrade…), lifecycle postStart/preStop, initContainers, commandes sh -c',
    'Conteneurs privilégiés, hostNetwork/PID/IPC, hostPath (et chemins sensibles : docker.sock, /etc, /root…), capacités Linux, root',
    'RBAC : jokers, cluster-admin, lecture des secrets ; ressources inhabituelles (webhooks, ClusterRole, DaemonSet, CronJob)',
    'Exposition : NodePort, LoadBalancer, externalIPs, hostPort ; annotations Ingress à risque (snippets, redirections)',
    'Redirections DNS (hostAliases), proxy forcé, NODE_OPTIONS, fonction Helm lookup, secrets versionnés, images non figées',
    'Configurations nginx/apache/scripts/JS embarquées dans les ConfigMaps (blocs YAML multi-lignes)',
    'Chart.yaml : dépôts de dépendances autorisés ; sous-charts vendorisés (.tgz) décompressés et analysés',
    '.gitlab-ci.yml : inclusions distantes, push/tag depuis le pipeline, envoi de tokens',
    'Motifs shell dangereux dans tous les fichiers YAML',
    'Rendu "helm template" si l\'outil helm est disponible',
  ],
  async run(ctx) {
    const findings = [];
    const ports = [];
    const images = [];
    const notes = [];
    let count = 0;
    for (const file of ctx.files.filter(isYaml)) {
      const text = ctx.readText(file);
      if (!text) continue;
      count++;
      findings.push(...scanText(text, SHELL_RULES, { file: file.rel, category: K, projectType: ctx.projectType }));
      if (/(^|\/)\.gitlab-ci\.ya?ml$|(^|\/)\.gitlab\/ci\//.test(file.rel) || /^\s*(stages|include):/m.test(text) && /^\s*script:/m.test(text)) {
        findings.push(...scanText(text, CI_RULES, { file: file.rel, category: K }));
      }
      if (!looksK8s(text, file.rel)) continue;
      findings.push(...scanK8sText(text, file.rel, ctx));
      const b = analyzeBlocks(text, file.rel, ctx);
      findings.push(...b.findings); ports.push(...b.ports);
      text.split(/\r?\n/).forEach((l, i) => {
        let m;
        if ((m = /^\s*-?\s*image:\s*["']?([^\s"'#]+)["']?\s*$/.exec(l))) images.push({ image: m[1], fichier: file.rel, ligne: i + 1 });
        if ((m = /^\s*-?\s*(containerPort|targetPort|port|nodePort):\s*(\d+)\s*$/.exec(l))) ports.push({ port: Number(m[2]), source: `k8s ${m[1]}`, fichier: file.rel, ligne: i + 1 });
        if ((m = /^\s*(repository|registry):\s*["']?([^\s"'#]+)["']?\s*$/.exec(l)) && /values/.test(file.base)) images.push({ image: m[2], fichier: file.rel, ligne: i + 1 });
      });
      // Chart.yaml
      if (/(^|\/)Chart\.ya?ml$/.test(file.rel)) {
        const allowed = ctx.config.helm.depotsAutorises || [];
        text.split(/\r?\n/).forEach((l, i) => {
          const m = /^\s*-?\s*repository:\s*["']?([^\s"']+)["']?/.exec(l);
          if (!m) return;
          const repo = m[1];
          if (repo.startsWith('file://') || repo.startsWith('@') || repo.startsWith('alias:')) return;
          if (/^http:\/\//.test(repo) || (allowed.length && !allowed.some(a => repo.startsWith(a)))) {
            findings.push(makeFinding({ id: 'HELM_DEPOT_NON_AUTORISE', sev: 'high', cat: K, review: true, title: 'Dépendance de chart depuis un dépôt non autorisé', desc: 'Un sous-chart est téléchargé depuis un dépôt non maîtrisé ou non chiffré (http).', fix: 'Utiliser le dépôt Helm d\'Artifactory.' }, { file: file.rel, line: i + 1, evidence: l.trim() }));
          }
        });
      }
    }
    // Images : registres autorisés
    const allowedReg = ctx.config.docker.registresAutorises || [];
    if (allowedReg.length) {
      for (const im of images) {
        if (im.image.includes('{{') || !im.image.includes('/')) continue;
        const reg = im.image.split('/')[0];
        if ((reg.includes('.') || reg.includes(':')) && !allowedReg.some(a => im.image.startsWith(a) || reg === a)) {
          findings.push(makeFinding({ id: 'K8S_REGISTRE_NON_AUTORISE', sev: 'medium', cat: K, review: true, title: 'Image provenant d\'un registre non autorisé', desc: 'L\'image déployée ne vient pas d\'un registre de la liste autorisée.', fix: 'Utiliser le registre d\'entreprise.' }, { file: im.fichier, line: im.ligne, evidence: im.image }));
        }
      }
    }
    // Sous-charts vendorisés
    for (const file of ctx.files.filter(f => /(^|\/)charts\/[^/]+\.tgz$/.test(f.rel))) {
      try {
        const entries = extractTgz(fs.readFileSync(file.abs), { filter: n => /\.(ya?ml|tpl|conf|sh|js)$/.test(n) });
        for (const e of entries) {
          if (!e.content) continue;
          const t = e.content.toString('utf8');
          const label = `${file.rel}!${e.name}`;
          findings.push(...scanK8sText(t, label, ctx));
          findings.push(...scanText(t, SHELL_RULES, { file: label, category: K }));
          findings.push(...analyzeBlocks(t, label, ctx).findings);
          count++;
        }
      } catch (e) { notes.push(`Sous-chart ${file.rel} illisible : ${e.message}`); }
    }
    // Rendu helm template
    const charts = ctx.files.filter(f => /(^|\/)Chart\.ya?ml$/.test(f.rel) && !f.rel.includes('charts/'));
    if (charts.length && ctx.tools.helm) {
      for (const c of charts) {
        const dir = path.dirname(c.abs);
        const rendered = renderHelm(ctx, dir);
        if (!rendered) { notes.push(`helm template a échoué pour ${c.rel} (dépendances non téléchargées ?) : analyse sur les templates bruts uniquement.`); continue; }
        const label = `${path.dirname(c.rel) || '.'} (rendu helm template)`;
        const known = new Set(findings.map(f => f.rule + '|' + (f.evidence || '')));
        const extra = scanK8sText(rendered, label, ctx).concat(analyzeBlocks(rendered, label, ctx).findings, scanText(rendered, SHELL_RULES, { file: label, category: K }));
        findings.push(...extra.filter(f => !known.has(f.rule + '|' + (f.evidence || ''))));
      }
    } else if (charts.length) {
      notes.push('helm non disponible : analyse des templates bruts uniquement (les valeurs ne sont pas substituées).');
    }
    return { findings, filesAnalyzed: count, inventory: { ports, images }, notes };
  },
};
