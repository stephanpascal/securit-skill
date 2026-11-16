'use strict';
/**
 * Exécution sécurisée de git : aucun shell, hooks neutralisés, protocole file interdit, LFS non téléchargé.
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

let emptyHooksDir = null;
function hooksDir() {
  if (!emptyHooksDir) {
    emptyHooksDir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-nohooks-'));
  }
  return emptyHooksDir;
}

function safeArgs() {
  return [
    '-c', 'core.hooksPath=' + hooksDir(),
    '-c', 'core.fsmonitor=false',
    '-c', 'protocol.file.allow=never',
    '-c', 'protocol.ext.allow=never',
    '-c', 'core.symlinks=false',
    '-c', 'submodule.recurse=false',
    '-c', 'core.longpaths=true',
  ];
}

function gitEnv() {
  return Object.assign({}, process.env, {
    GIT_TERMINAL_PROMPT: '0',
    GIT_LFS_SKIP_SMUDGE: '1',
    // La config système/utilisateur est conservée : elle contient le gestionnaire d'identifiants et le proxy d'entreprise.
  });
}

function git(args, cwd, opts = {}) {
  return execFileSync('git', safeArgs().concat(args), {
    cwd,
    env: gitEnv(),
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: opts.timeout || 10 * 60 * 1000,
    windowsHide: true,
  });
}

function tryGit(args, cwd, opts) {
  try { return git(args, cwd, opts); } catch { return null; }
}

module.exports = { git, tryGit };
