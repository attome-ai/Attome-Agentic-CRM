# Attome one-command install for Windows (roadmap U1-T1).
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/attome-ai/Attome-Agentic-CRM/main/scripts/install.ps1))) `
#       -DatabaseUrl 'postgres://attome_owner:secret@127.0.0.1:5432/attome' -Admin you@example.com
#
# Run from an elevated PowerShell. Downloads the release archive (attome.exe
# and the web app) into %ProgramFiles%\Attome, checks its SHA-256, then runs
# `attome init --service`, which writes %ProgramData%\Attome\config.json,
# applies the schema, creates the first administrator and starts the
# Windows service.
#
# PostgreSQL 18 with the pgvector, pg_trgm and pgcrypto extensions must
# already exist on Windows: -DatabaseUrl names a database owned by a role
# with CREATEROLE, where a superuser has already run
#   CREATE EXTENSION vector; CREATE EXTENSION pg_trgm; CREATE EXTENSION pgcrypto;
# (pgvector publishes no Windows build to install automatically.)
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)] [string] $DatabaseUrl,
  [string] $Admin = '',
  [string] $Version = 'latest',
  [int] $Port = 7865,
  [string] $Prefix = (Join-Path $env:ProgramFiles 'Attome'),
  [string[]] $Packs = @('crm')
)

$ErrorActionPreference = 'Stop'
$repo = 'attome-ai/Attome-Agentic-CRM'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'install.ps1: run from an elevated PowerShell (Run as administrator).'
}
if (-not [Environment]::Is64BitOperatingSystem) {
  throw 'install.ps1: only x86_64 builds are published so far.'
}

$asset = 'attome-windows-x86_64.zip'
$base = if ($Version -eq 'latest') {
  "https://github.com/$repo/releases/latest/download"
} else {
  "https://github.com/$repo/releases/download/$Version"
}
$work = Join-Path ([IO.Path]::GetTempPath()) ("attome-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
  Write-Host "downloading $asset ($Version)..."
  $zip = Join-Path $work $asset
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $zip
  Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset.sha256" -OutFile "$zip.sha256"
  $expected = ((Get-Content "$zip.sha256" -Raw).Trim() -split '\s+')[0].ToLower()
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) { throw "install.ps1: the download's checksum does not match" }

  New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
  Expand-Archive -Path $zip -DestinationPath $Prefix -Force
} finally {
  Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
}

$exe = Join-Path $Prefix 'attome.exe'
$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if (($machinePath -split ';') -notcontains $Prefix) {
  [Environment]::SetEnvironmentVariable('Path', "$machinePath;$Prefix", 'Machine')
}

$initArgs = @('init', '--database-url', $DatabaseUrl, '--port', "$Port", '--service')
if ($Admin) { $initArgs += @('--admin', $Admin) }
foreach ($pack in $Packs) { if ($pack) { $initArgs += @('--pack', $pack) } }
& $exe @initArgs
if ($LASTEXITCODE -ne 0) { throw "install.ps1: attome init failed ($LASTEXITCODE)" }
