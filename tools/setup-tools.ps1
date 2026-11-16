<#
.SYNOPSIS
  Télécharge les outils externes OPTIONNELS dans tools\bin (aucun droit administrateur requis).
  L'audit fonctionne sans eux ; s'ils sont présents, ils complètent l'analyse.

.DESCRIPTION
  Si le réseau d'entreprise bloque GitHub, télécharger les fichiers manuellement (ou depuis un dépôt
  "generic" Artifactory) et déposer les exécutables dans tools\bin :
    gitleaks.exe, trivy.exe, osv-scanner.exe, hadolint.exe, helm.exe, kube-linter.exe
  Les empreintes SHA256 sont affichées : les comparer aux fichiers checksums publiés par chaque projet.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\setup-tools.ps1
  powershell -ExecutionPolicy Bypass -File tools\setup-tools.ps1 -Only gitleaks,trivy
#>
param([string[]]$Only)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try { [System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials } catch {}

$bin = Join-Path $PSScriptRoot 'bin'
$tmp = Join-Path $PSScriptRoot '.download'
New-Item -ItemType Directory -Force -Path $bin, $tmp | Out-Null

$tools = @(
  @{ name = 'gitleaks';    url = 'https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_windows_x64.zip'; exe = 'gitleaks.exe' },
  @{ name = 'trivy';       url = 'https://github.com/aquasecurity/trivy/releases/download/v0.57.1/trivy_0.57.1_windows-64bit.zip'; exe = 'trivy.exe' },
  @{ name = 'osv-scanner'; url = 'https://github.com/google/osv-scanner/releases/download/v1.9.1/osv-scanner_windows_amd64.exe'; exe = 'osv-scanner.exe' },
  @{ name = 'hadolint';    url = 'https://github.com/hadolint/hadolint/releases/download/v2.12.0/hadolint-Windows-x86_64.exe'; exe = 'hadolint.exe' },
  @{ name = 'helm';        url = 'https://get.helm.sh/helm-v3.16.3-windows-amd64.zip'; exe = 'helm.exe' },
  @{ name = 'kube-linter'; url = 'https://github.com/stackrox/kube-linter/releases/download/v0.6.8/kube-linter.exe'; exe = 'kube-linter.exe' }
)

foreach ($t in $tools) {
  if ($Only -and ($Only -notcontains $t.name)) { continue }
  $dest = Join-Path $bin $t.exe
  if (Test-Path $dest) { Write-Host "[ok]   $($t.name) déjà présent"; continue }
  try {
    $file = Join-Path $tmp ([System.IO.Path]::GetFileName($t.url))
    Write-Host "[...]  $($t.name) : $($t.url)"
    Invoke-WebRequest -Uri $t.url -OutFile $file -UseBasicParsing
    Write-Host "       SHA256 : $((Get-FileHash $file -Algorithm SHA256).Hash)"
    if ($file.EndsWith('.zip')) {
      $x = Join-Path $tmp $t.name
      Expand-Archive -Path $file -DestinationPath $x -Force
      $found = Get-ChildItem -Path $x -Recurse -Filter $t.exe | Select-Object -First 1
      if (-not $found) { throw "$($t.exe) introuvable dans l'archive" }
      Copy-Item $found.FullName $dest
    } else {
      Copy-Item $file $dest
    }
    Write-Host "[ok]   $($t.name) installé dans $dest"
  } catch {
    Write-Warning "$($t.name) : échec ($($_.Exception.Message)). Téléchargement manuel possible, puis copier $($t.exe) dans $bin"
  }
}
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Write-Host "`nNote : trivy télécharge sa base de vulnérabilités au premier lancement (accès à ghcr.io requis) ; en mode --offline elle n'est pas mise à jour."
