'use strict';
/**
 * Clonage sécurisé du dépôt à analyser.
 * - pas de sous-modules, hooks neutralisés, protocole file:// et ext:: interdits, LFS non téléchargé
 * - aucune commande du projet n'est exécutée
 */
const fs = require('fs');
const path = require('path');
const { git, tryGit } = require('./git');
const { sanitizeUrl } = require('./sanitize');

function validateUrl(url) {
  if (/^https:\/\/[^\s]+$/i.test(url)) return 'https';
  if (/^ssh:\/\/[^\s]+$/i.test(url)) return 'ssh';
  if (/^[\w.-]+@[\w.-]+:[^\s]+$/.test(url)) return 'ssh';
  throw new Error(`URL refusée : "${url}". Formats acceptés : https://…, ssh://… ou git@hote:groupe/projet.git`);
}

/** Extrait l'hôte et le chemin du projet (groupe/sous-groupe/projet) depuis une URL GitLab. */
function parseGitlabUrl(url) {
  let m = /^https?:\/\/(?:[^@\/]+@)?([^\/:]+)(?::\d+)?\/(.+?)(?:\.git)?\/?$/i.exec(url);
  if (m) return { host: m[1], projectPath: m[2] };
  m = /^ssh:\/\/(?:[^@\/]+@)?([^\/:]+)(?::\d+)?\/(.+?)(?:\.git)?\/?$/i.exec(url);
  if (m) return { host: m[1], projectPath: m[2] };
  m = /^[\w.-]+@([\w.-]+):(.+?)(?:\.git)?\/?$/.exec(url);
  if (m) return { host: m[1], projectPath: m[2] };
  return null;
}

function cloneRepo(url, dest, { ref, shallow, log } = {}) {
  validateUrl(url);
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  const args = ['clone', '--no-recurse-submodules', '--quiet'];
  if (shallow) args.push('--depth', '1');
  if (ref) args.push('--branch', ref);
  args.push('--', url, dest);
  log && log(`Clonage sécurisé de ${sanitizeUrl(url)}${ref ? ' (ref ' + ref + ')' : ''}${shallow ? ' [superficiel]' : ''}…`);
  git(args, process.cwd(), { timeout: 20 * 60 * 1000 });
  return repoInfo(dest);
}

function repoInfo(dir) {
  const isRepo = fs.existsSync(path.join(dir, '.git'));
  if (!isRepo) return { isRepo: false };
  const commit = (tryGit(['rev-parse', 'HEAD'], dir) || '').trim();
  const branch = (tryGit(['rev-parse', '--abbrev-ref', 'HEAD'], dir) || '').trim();
  const shallow = (tryGit(['rev-parse', '--is-shallow-repository'], dir) || '').trim() === 'true';
  let defaultBranch = (tryGit(['symbolic-ref', '--short', 'refs/remotes/origin/HEAD'], dir) || '').trim().replace(/^origin\//, '');
  if (!defaultBranch) defaultBranch = branch;
  const commitDate = (tryGit(['log', '-1', '--format=%cI'], dir) || '').trim();
  return { isRepo: true, commit, branch, defaultBranch, shallow, commitDate };
}

function removeDir(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 }); return true; } catch { return false; }
}

module.exports = { cloneRepo, repoInfo, removeDir, validateUrl, parseGitlabUrl };
