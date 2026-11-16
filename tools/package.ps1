<#
.SYNOPSIS
  Crée une archive propre du projet, sans les fichiers générés (tests\.tmp, reports, workspace),
  sans configuration locale ni outils téléchargés.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\package.ps1
  powershell -ExecutionPolicy Bypass -File tools\package.ps1 -Destination D:\transfert\skill-analyse.zip
#>
param([string]$Destination = (Join-Path (Split-Path (Split-Path $PSScriptRoot)) 'skill-analyse.zip'))
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$exclude = '^(tests\\\.tmp|reports|workspace|tools\\bin|tools\\\.download|node_modules|\.git)(\\|$)|^config\\settings\.local\.json$|\.(zip|7z|rar|tgz|log|iml)$'

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ('skill-analyse-' + [guid]::NewGuid().ToString('N'))
$target = Join-Path $staging 'skill-analyse'
$count = 0
Get-ChildItem -Path $root -Recurse -File -Force | ForEach-Object {
  $rel = $_.FullName.Substring($root.Length + 1)
  if ($rel -match $exclude) { return }
  $dest = Join-Path $target $rel
  New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
  Copy-Item $_.FullName $dest
  $count++
}
if (Test-Path $Destination) { Remove-Item $Destination -Force }
Compress-Archive -Path $target -DestinationPath $Destination
Remove-Item -Recurse -Force $staging
Write-Host "$count fichiers archivés dans $Destination"
