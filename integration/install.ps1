<#
.SYNOPSIS
  Installe le skill / prompt "security-audit" pour GitHub Copilot (et optionnellement Claude Code).
  Aucun droit administrateur requis : tout est copié dans le profil utilisateur.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File integration\install.ps1
  powershell -ExecutionPolicy Bypass -File integration\install.ps1 -Claude
  powershell -ExecutionPolicy Bypass -File integration\install.ps1 -VSCodeUserDir "$env:APPDATA\Code - Insiders\User"
#>
param(
  [switch]$Claude,
  [switch]$NoCopilotSkill,
  [switch]$NoPrompt,
  [string]$VSCodeUserDir = (Join-Path $env:APPDATA 'Code\User')
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$auditHome = $root -replace '\\', '/'
$utf8 = New-Object System.Text.UTF8Encoding $false

function Install-Template([string]$src, [string]$dest) {
  $content = [System.IO.File]::ReadAllText($src, [System.Text.Encoding]::UTF8).Replace('{{AUDIT_HOME}}', $auditHome)
  New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
  [System.IO.File]::WriteAllText($dest, $content, $utf8)
  Write-Host "  installé : $dest"
}

Write-Host "Dossier de l'outil : $auditHome"
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { Write-Warning "Node.js introuvable dans le PATH : l'audit ne pourra pas s'exécuter." } else { Write-Host "Node.js : $(& node -v)" }
$git = Get-Command git -ErrorAction SilentlyContinue
if (-not $git) { Write-Warning "git introuvable dans le PATH : le clonage ne pourra pas s'exécuter." }

if (-not $NoCopilotSkill) {
  Write-Host "Skill Copilot (~/.copilot/skills) :"
  Install-Template (Join-Path $root 'integration\copilot\skills\security-audit\SKILL.md') (Join-Path $env:USERPROFILE '.copilot\skills\security-audit\SKILL.md')
}
if (-not $NoPrompt) {
  Write-Host "Prompt Copilot (profil VS Code) :"
  Install-Template (Join-Path $root 'integration\copilot\prompts\security-audit.prompt.md') (Join-Path $VSCodeUserDir 'prompts\security-audit.prompt.md')
}
if ($Claude) {
  Write-Host "Skill Claude Code (~/.claude/skills) :"
  Install-Template (Join-Path $root 'integration\claude\skills\security-audit\SKILL.md') (Join-Path $env:USERPROFILE '.claude\skills\security-audit\SKILL.md')
}

$local = Join-Path $root 'config\settings.local.json'
if (-not (Test-Path $local)) {
  Copy-Item (Join-Path $root 'config\settings.json') $local
  Write-Host "Configuration locale créée : $local (à compléter : URL Artifactory, domaine GitLab, domaines email…)"
}
Write-Host ""
Write-Host "Terminé. Dans Copilot Chat (mode Agent) : /security-audit fe01 https://gitlab.exemple.fr/groupe/fe01.git"
Write-Host "Pour les contrôles GitLab (MR, approbations) : `$env:GITLAB_TOKEN = '<token read_api>'  (ou variable d'environnement utilisateur)"
