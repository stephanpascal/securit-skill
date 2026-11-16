'use strict';
/**
 * Configurations d'IDE et d'assistants IA versionnées dans le dépôt :
 * exécution automatique à l'ouverture du dossier (VS Code, devcontainer, IntelliJ), serveurs MCP,
 * hooks d'assistants, fichiers d'instructions IA (injection de consignes).
 */
const { scanText, scanLines } = require('../lib/patterns');
const { SHELL_RULES } = require('../lib/shell-rules');
const { makeFinding } = require('../lib/finding');
const { truncate } = require('../lib/util');

const I = 'ide';
const R = {
  TASK_AUTO: { id: 'IDE_TACHE_AUTOMATIQUE', sev: 'high', review: true, title: 'Tâche VS Code exécutée automatiquement à l\'ouverture du dossier (runOn: folderOpen)', desc: 'Ouvrir le dépôt dans VS Code suffit à lancer cette commande. Technique de la campagne « Contagious Interview » (faux tests techniques, dépôts GitHub compromis).', fix: 'Supprimer runOn: folderOpen ; laisser task.allowAutomaticTasks désactivé sur les postes.' },
  TASK_AUTO_DANGER: { id: 'IDE_TACHE_AUTOMATIQUE_DANGEREUSE', sev: 'critical', title: 'Tâche automatique à l\'ouverture exécutant une commande dangereuse ou un faux fichier', desc: 'La tâche lancée à l\'ouverture du dossier télécharge/exécute du code ou lance avec Node un fichier qui n\'est pas du JavaScript (ex. fausse police .woff2).', fix: 'Ne pas ouvrir ce dépôt dans un IDE avant nettoyage ; supprimer la tâche et le fichier exécuté.' },
  TASK_CMD: { id: 'IDE_TACHE_COMMANDE_DANGEREUSE', sev: 'high', review: true, title: 'Tâche VS Code contenant une commande dangereuse', desc: 'Une tâche versionnée exécute une commande à risque (lancée par un développeur via « Run Task »).', fix: 'Relire la tâche.' },
  SETTINGS_AUTOTASK: { id: 'IDE_TACHES_AUTO_AUTORISEES', sev: 'high', title: 'Le dépôt autorise l\'exécution automatique des tâches (task.allowAutomaticTasks)', desc: 'Le paramètre versionné active l\'exécution automatique des tâches à l\'ouverture.', fix: 'Supprimer ce paramètre du dépôt.' },
  SETTINGS_TRUST: { id: 'IDE_CONFIANCE_DESACTIVEE', sev: 'high', title: 'Paramètre désactivant une protection de l\'IDE', desc: 'Désactivation de la confiance de l\'espace de travail ou approbation automatique des outils de l\'assistant IA.', fix: 'Supprimer ce paramètre du dépôt.' },
  SETTINGS_EXEC: { id: 'IDE_CHEMIN_EXECUTABLE', sev: 'medium', review: true, title: 'Paramètre IDE remplaçant le chemin d\'un exécutable', desc: 'Un paramètre de type *.path / executablePath / interpreterPath pointe vers un fichier du dépôt ou inhabituel : l\'IDE l\'exécutera.', fix: 'Vérifier le fichier pointé.' },
  DEVCONTAINER_HOST: { id: 'IDE_DEVCONTAINER_COMMANDE_HOTE', sev: 'high', review: true, title: 'devcontainer : commande exécutée sur le poste hôte (initializeCommand)', desc: 'initializeCommand s\'exécute directement sur la machine du développeur, hors conteneur.', fix: 'Relire la commande.' },
  DEVCONTAINER_CMD: { id: 'IDE_DEVCONTAINER_COMMANDE', sev: 'low', review: true, title: 'devcontainer : commande exécutée à la création/au démarrage', desc: 'postCreateCommand / postStartCommand… s\'exécutent automatiquement dans le conteneur de développement (qui a souvent accès aux identifiants git et aux fichiers).', fix: 'Relire la commande.' },
  MCP: { id: 'IA_SERVEUR_MCP', sev: 'medium', review: true, title: 'Serveur MCP déclaré dans le dépôt', desc: 'L\'assistant IA (Copilot, Claude, Cursor…) lancera ce programme et lui donnera accès à la conversation et aux outils.', fix: 'Vérifier le programme lancé ; un paquet téléchargé à la volée (npx -y) est particulièrement risqué.' },
  MCP_DANGER: { id: 'IA_SERVEUR_MCP_DANGEREUX', sev: 'high', review: true, title: 'Serveur MCP téléchargé à la volée ou commande dangereuse', desc: 'Le serveur MCP est téléchargé à chaque lancement (npx -y, uvx, URL) ou sa commande contient un motif dangereux.', fix: 'Supprimer ou figer une version relue.' },
  AI_HOOKS: { id: 'IA_HOOKS_ASSISTANT', sev: 'high', review: true, title: 'Hooks ou permissions d\'assistant IA versionnés', desc: 'Des commandes exécutées automatiquement par l\'assistant (hooks) ou des permissions élargies (Bash(*)) sont imposées par le dépôt.', fix: 'Relire et supprimer du dépôt si non nécessaire.' },
  AI_INSTR: { id: 'IA_FICHIER_INSTRUCTIONS', sev: 'info', review: true, title: 'Fichier d\'instructions pour assistant IA', desc: 'Ce fichier est lu automatiquement par l\'assistant (Copilot, Claude, Cursor…) et oriente son comportement sur ce dépôt.', fix: 'Vérifier son contenu.' },
  AI_INJECTION: { id: 'IA_INJECTION_CONSIGNES', sev: 'high', review: true, title: 'Consigne suspecte dans un fichier d\'instructions IA', desc: 'Le fichier demande à l\'assistant d\'ignorer ses consignes, d\'agir sans prévenir, de lancer des commandes réseau ou de manipuler des secrets (« Rules File Backdoor »).', fix: 'Supprimer la consigne ; ne pas utiliser d\'assistant en mode agent sur ce dépôt avant nettoyage.' },
  IDEA: { id: 'IDE_INTELLIJ_EXECUTION', sev: 'medium', review: true, title: 'Configuration d\'exécution IntelliJ avec script ou outil externe', desc: 'Une configuration versionnée lance un script shell ou un outil externe.', fix: 'Relire la configuration.' },
};
for (const r of Object.values(R)) r.cat = I;

const INJECTION_RE = /ignore[rz]?\s+(all\s+|the\s+|toutes?\s+les\s+|les\s+)?(previous|prior|above|earlier|system|précédentes?|instructions?\s+précédentes?|consignes?)|(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show)\s+(this\s+)?(to\s+)?the\s+user|ne\s+(dis|mentionne|signale|montre)\s+(rien|pas)\s+(à\s+)?l'?utilisateur|without\s+(asking|confirmation|telling)|sans\s+(demander|confirmation|prévenir)|\b(curl|wget|Invoke-WebRequest|iwr)\b|base64\s+(-d|--decode)|\.ssh\/|id_rsa|\.npmrc|\.aws\/credentials|exfiltrat|send\s+.{0,40}\s+to\s+https?:|envoie\s+.{0,40}\s+(à|vers)\s+https?:|--dangerously-skip-permissions|--yolo|run\s+the\s+following\s+command|exécute\s+(la|cette)\s+commande/i;
const AI_FILES = /(^|\/)(\.github\/copilot-instructions\.md|\.github\/instructions\/[^/]+\.md|\.github\/prompts\/[^/]+\.md|\.github\/chatmodes\/[^/]+|\.github\/agents\/[^/]+|AGENTS\.md|CLAUDE\.md|GEMINI\.md|\.cursorrules|\.cursor\/rules\/[^/]+|\.windsurfrules|\.clinerules(\/[^/]+)?|\.roorules|\.continue\/[^/]+|\.junie\/guidelines\.md|\.claude\/(commands|agents|skills)\/.+)$/i;
const MCP_FILES = /(^|\/)(\.vscode\/mcp\.json|\.mcp\.json|mcp\.json|\.cursor\/mcp\.json|\.gemini\/settings\.json|\.roo\/mcp\.json|\.amazonq\/mcp\.json|\.continue\/mcpServers\/[^/]+)$/i;
const NOT_JS_EXT = /\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|svg|txt|css|md|json|map|dat|bin|log|csv)$/i;

/** JSON avec commentaires et virgules finales (format des fichiers .vscode). */
function parseJsonc(text) {
  let out = ''; let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inStr) { out += c; if (c === '\\') { out += text[++i] || ''; } else if (c === '"') inStr = false; continue; }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && text[i + 1] === '*') { i += 2; while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, '$1').replace(/^﻿/, ''));
}

function lineOf(text, needle) {
  if (!needle) return null;
  const i = text.indexOf(needle);
  return i < 0 ? null : text.slice(0, i).split('\n').length;
}

function cmdOf(t) {
  const parts = [t.command, ...(Array.isArray(t.args) ? t.args : [])];
  for (const os of ['windows', 'linux', 'osx']) if (t[os]) parts.push(t[os].command, ...(t[os].args || []));
  return parts.filter(Boolean).map(p => (typeof p === 'string' ? p : (p.value || JSON.stringify(p)))).join(' ');
}

module.exports = {
  id: 'ide-ai',
  label: 'Configurations IDE et assistants IA',
  category: I,
  controls: [
    'VS Code : tâches exécutées à l\'ouverture du dossier (runOn: folderOpen), commandes dangereuses, faux fichiers lancés avec Node (fausses polices / images)',
    'VS Code : paramètres versionnés activant les tâches automatiques, désactivant la confiance ou auto-approuvant les outils de l\'assistant, chemins d\'exécutables remplacés',
    'devcontainer : initializeCommand (exécutée sur le poste hôte), postCreateCommand / postStartCommand…',
    'IntelliJ : configurations d\'exécution lançant des scripts ou outils externes',
    'Serveurs MCP déclarés (.vscode/mcp.json, .mcp.json, .cursor…), téléchargés à la volée',
    'Hooks et permissions d\'assistants IA (.claude/settings.json…)',
    'Fichiers d\'instructions IA (copilot-instructions.md, AGENTS.md, CLAUDE.md, .cursorrules…) et consignes suspectes (injection)',
  ],
  async run(ctx) {
    const findings = [];
    let count = 0;
    const at = (rule, file, text, needle, data) => findings.push(makeFinding(rule, Object.assign({ file: file.rel, line: lineOf(text, needle), evidence: truncate(needle || '', 250) }, data)));

    for (const file of ctx.files) {
      const rel = file.rel;
      const text = ctx.readText(file);
      if (text == null) continue;

      // --- VS Code tasks.json ---
      if (/(^|\/)\.vscode\/tasks\.json$/i.test(rel)) {
        count++;
        let json = null;
        try { json = parseJsonc(text); } catch { /* illisible : analyse texte */ }
        const tasks = json && Array.isArray(json.tasks) ? json.tasks : [];
        for (const t of tasks) {
          const cmd = cmdOf(t);
          const auto = t.runOptions && /folderOpen/i.test(String(t.runOptions.runOn || ''));
          const danger = scanLines([{ n: 1, text: cmd }], SHELL_RULES, { file: rel, category: I });
          const nodeFake = /\b(node|nodejs|bun|deno)(\.exe)?\s+["']?([^\s"']+)/i.exec(cmd);
          const fake = nodeFake && NOT_JS_EXT.test(nodeFake[3]);
          const label = `tâche « ${t.label || t.taskName || '?'} » : ${cmd}`;
          const needle = t.label ? `"${t.label}"` : (typeof t.command === 'string' ? t.command : null);
          if (auto && (danger.length || fake)) at(R.TASK_AUTO_DANGER, file, text, needle, { evidence: label + (fake ? ` — fichier exécuté non JavaScript : ${nodeFake[3]}` : ` — ${danger[0].title}`) });
          else if (auto) at(R.TASK_AUTO, file, text, needle, { evidence: label });
          else if (danger.length || fake) at(R.TASK_CMD, file, text, needle, { evidence: label });
        }
        if (!json && /folderOpen/.test(text)) at(R.TASK_AUTO, file, text, 'folderOpen', { evidence: 'runOn: folderOpen (fichier tasks.json non analysable)' });
        continue;
      }
      // --- VS Code settings.json / *.code-workspace ---
      if (/(^|\/)\.vscode\/settings\.json$|\.code-workspace$/i.test(rel)) {
        count++;
        let m;
        if ((m = /"task\.allowAutomaticTasks"\s*:\s*"?(on|true)"?/i.exec(text))) at(R.SETTINGS_AUTOTASK, file, text, m[0]);
        const trustRe = /"(security\.workspace\.trust\.enabled"\s*:\s*false|chat\.tools\.(global\.)?autoApprove"\s*:\s*true|chat\.tools\.terminal\.autoApprove"\s*:|github\.copilot\.chat\.agent\.autoApprove"\s*:\s*true|chat\.agent\.autoApprove"\s*:\s*true)/gi;
        while ((m = trustRe.exec(text))) at(R.SETTINGS_TRUST, file, text, m[0]);
        const execRe = /"([\w.-]+(?:\.path|Path|\.command|\.executable))"\s*:\s*"([^"]+)"/g;
        while ((m = execRe.exec(text))) {
          if (/^(true|false|auto|default)$/i.test(m[2]) || /(exclude|include|watcher|search|files)\./i.test(m[1])) continue;
          at(R.SETTINGS_EXEC, file, text, m[0], { severity: /^\.{0,2}[\\/]|\$\{workspaceFolder\}|\.(sh|bat|cmd|ps1|js)$/i.test(m[2]) ? 'high' : 'medium' });
        }
        findings.push(...scanText(text, SHELL_RULES, { file: rel, category: I, maxPerRule: 2 }));
        continue;
      }
      // --- launch.json ---
      if (/(^|\/)\.vscode\/launch\.json$/i.test(rel)) {
        count++;
        findings.push(...scanText(text, SHELL_RULES, { file: rel, category: I, maxPerRule: 2 }));
        continue;
      }
      // --- devcontainer ---
      if (/(^|\/)\.devcontainer(\/[^/]+)?\/devcontainer\.json$|(^|\/)\.devcontainer\.json$/i.test(rel)) {
        count++;
        let json = null;
        try { json = parseJsonc(text); } catch { /* ignore */ }
        if (json) {
          for (const k of ['initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand']) {
            if (!json[k]) continue;
            const cmd = typeof json[k] === 'string' ? json[k] : JSON.stringify(json[k]);
            const danger = scanLines([{ n: 1, text: cmd }], SHELL_RULES, { file: rel, category: I });
            const rule = k === 'initializeCommand' ? R.DEVCONTAINER_HOST : R.DEVCONTAINER_CMD;
            at(rule, file, text, `"${k}"`, { evidence: `${k} : ${cmd}`, severity: danger.length ? 'critical' : rule.sev });
          }
        }
        continue;
      }
      // --- IntelliJ ---
      if (/(^|\/)\.idea\/.+\.xml$|(^|\/)\.run\/.+\.run\.xml$/i.test(rel)) {
        count++;
        const m = /ShConfigurationType|SCRIPT_TEXT|<option name="(INTERPRETER_PATH|SCRIPT_PATH)"|ExternalTools|BeforeRunTask|<tool name=/.exec(text);
        if (m) at(R.IDEA, file, text, m[0]);
        findings.push(...scanText(text, SHELL_RULES, { file: rel, category: I, maxPerRule: 2 }));
        continue;
      }
      // --- Serveurs MCP ---
      if (MCP_FILES.test(rel)) {
        count++;
        let json = null;
        try { json = parseJsonc(text); } catch { /* ignore */ }
        const servers = json ? Object.assign({}, json.servers, json.mcpServers, json.mcp && json.mcp.servers) : {};
        for (const [name, s] of Object.entries(servers)) {
          const cmd = [s.command, ...(s.args || [])].filter(Boolean).join(' ') || s.url || '';
          const fetched = /\b(npx|pnpx|bunx|uvx|pipx\s+run)\b|\bdlx\b|^https?:\/\//i.test(cmd);
          const danger = scanLines([{ n: 1, text: cmd }], SHELL_RULES, { file: rel, category: I });
          at(fetched || danger.length ? R.MCP_DANGER : R.MCP, file, text, `"${name}"`, { evidence: `serveur MCP « ${name} » : ${cmd}` });
        }
        if (!json && /"command"\s*:/.test(text)) at(R.MCP, file, text, '"command"', { evidence: 'serveur MCP (fichier non analysable)' });
        continue;
      }
      // --- Hooks / permissions d'assistants ---
      if (/(^|\/)\.claude\/settings(\.local)?\.json$|(^|\/)\.gemini\/settings\.json$|(^|\/)\.cursor\/hooks\.json$/i.test(rel)) {
        count++;
        const m = /"hooks"\s*:|"Bash\(\*\)"|"Bash\([^)]*(curl|wget|sh)[^)]*\)"|"defaultMode"\s*:\s*"bypassPermissions"|"dangerously/i.exec(text);
        if (m) at(R.AI_HOOKS, file, text, m[0]);
        findings.push(...scanText(text, SHELL_RULES, { file: rel, category: I, maxPerRule: 2 }));
      }
      // --- Fichiers d'instructions IA ---
      if (AI_FILES.test(rel)) {
        count++;
        at(R.AI_INSTR, file, text, null, { evidence: rel });
        const lines = text.split(/\r?\n/);
        let hits = 0;
        lines.forEach((l, i) => {
          if (hits >= 5) return;
          const m = INJECTION_RE.exec(l);
          if (m) { hits++; findings.push(makeFinding(R.AI_INJECTION, { file: rel, line: i + 1, evidence: truncate(l.trim(), 250) })); }
        });
      }
    }
    return { findings, filesAnalyzed: count, notes: count ? [] : ['Aucune configuration d\'IDE ou d\'assistant IA versionnée.'] };
  },
  parseJsonc,
};
