<#
.SYNOPSIS
  Runs every cargo-fuzz target in the repository for a set time and fails on
  a crash (roadmap Y13-T5).

.DESCRIPTION
  Finds each fuzz crate (crates/**/fuzz/Cargo.toml with
  [package.metadata] cargo-fuzz = true), lists its targets from the
  fuzz_targets folder, and runs each one with
  `cargo +nightly fuzz run <target> -- -max_total_time=<Seconds>`.

  cargo-fuzz needs a nightly toolchain and libFuzzer, which build on Linux and
  macOS. On Windows the script runs each target under WSL (`wsl.exe`), in the
  same checkout through /mnt/<drive>. The fuzz crates are developer tools:
  none is a workspace member and the Attome binary never depends on one.

  A crash leaves its input under <crate>/fuzz/artifacts/<target>/; the script
  names it and exits 1. With no crash it prints "no crashes" and exits 0.

.PARAMETER Seconds
  How long each target runs. Default 300.

.PARAMETER Target
  Run only the targets whose name contains this text.

.EXAMPLE
  pwsh -File scripts/fuzz-all.ps1 -Seconds 30
#>
[CmdletBinding()]
param(
    [int]$Seconds = 300,
    [string]$Target = ''
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$onWindows = [System.Environment]::OSVersion.Platform -eq 'Win32NT'

function ConvertTo-WslPath([string]$path) {
    $full = (Resolve-Path $path).Path
    if ($full -match '^([A-Za-z]):\\(.*)$') {
        return '/mnt/' + $Matches[1].ToLower() + '/' + ($Matches[2] -replace '\\', '/')
    }
    throw "cannot map $full to a WSL path"
}

function Invoke-Fuzz([string]$crate, [string]$name) {
    $run = "cargo +nightly fuzz run $name -- -max_total_time=$Seconds"
    if ($onWindows) {
        $dir = ConvertTo-WslPath $crate
        & wsl.exe -- bash -lc "cd '$dir' && $run" | Out-Host
    } else {
        Push-Location $crate
        try { & bash -lc $run | Out-Host } finally { Pop-Location }
    }
    return $LASTEXITCODE
}

if ($onWindows -and -not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
    [Console]::Error.WriteLine('cargo-fuzz needs Linux: install WSL (wsl --install), then nightly Rust and cargo-fuzz inside it.')
    exit 2
}

$crates = Get-ChildItem -Path (Join-Path $root 'crates') -Recurse -Filter Cargo.toml |
    Where-Object { $_.Directory.Name -eq 'fuzz' -and $_.FullName -notmatch '[\\/]target[\\/]' } |
    Where-Object { (Get-Content $_.FullName -Raw) -match 'cargo-fuzz\s*=\s*true' } |
    ForEach-Object { $_.Directory.FullName } |
    Sort-Object

if (-not $crates) {
    [Console]::Error.WriteLine('no fuzz crates found under crates/')
    exit 2
}

$failed = @()
$ran = 0
foreach ($crate in $crates) {
    $targets = Get-ChildItem -Path (Join-Path $crate 'fuzz_targets') -Filter *.rs |
        ForEach-Object { $_.BaseName } |
        Where-Object { $Target -eq '' -or $_ -like "*$Target*" } |
        Sort-Object
    foreach ($name in $targets) {
        $rel = $crate.Substring($root.Length).TrimStart([char]'\', [char]'/')
        Write-Host "==> $rel :: $name ($Seconds s)"
        $code = Invoke-Fuzz $crate $name
        $ran++
        if ($code -ne 0) {
            $artifacts = Join-Path $crate "artifacts/$name"
            Write-Host "    CRASH (exit $code); inputs under $artifacts"
            $failed += "$rel :: $name"
        } else {
            Write-Host '    ok'
        }
    }
}

if ($ran -eq 0) {
    [Console]::Error.WriteLine("no fuzz target matches '$Target'")
    exit 2
}
if ($failed.Count -gt 0) {
    Write-Host "$($failed.Count) of $ran targets crashed:"
    $failed | ForEach-Object { Write-Host "  $_" }
    exit 1
}
Write-Host "$ran targets ran $Seconds s each: no crashes"
exit 0
