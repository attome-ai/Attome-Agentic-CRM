# AB7-T10: proves a restart drains under load. Load runs (k6 crud_read.js and
# mutating_write.js together) while the server is replaced, and the run fails
# if k6 counts a single failed request.
#
#   single   one node under `attome supervise`; POST /restart at 30 s and 70 s.
#   rolling  two nodes, each under its own supervisor, behind the loadtest
#            nginx (docker-compose.loadtest.yml, profile "drain"): node 1 is
#            stopped (POST /stop drains it), started again and waited for,
#            then node 2.
#
# Writes docs/evidence/drain-<date>-<mode>.md (hardware, method, request
# counts, failures). Needs docker-compose.loadtest.yml up, seed.ps1 run, and
# $env:LOADTEST_ACK = 'yes'. -Plan prints the steps and exits.
#
#   ./run-drain-exercise.ps1 -Mode single -Plan
#   ./run-drain-exercise.ps1 -Mode rolling
param(
    [ValidateSet("single", "rolling")]
    [string]$Mode = "single",
    [switch]$Plan,
    # 0: 120 s for single, 300 s for rolling (two node starts fit in it).
    [int]$DurationSecs = 0,
    [string]$Vus = ""
)

if ($DurationSecs -le 0) {
    $DurationSecs = if ($Mode -eq "single") { 120 } else { 300 }
}

$planSteps = @{
    single  = @(
        "Check LOADTEST_ACK, the loadtest database name and seed.ps1's seed-info.json.",
        "Start 'attome supervise' on 0.0.0.0:7900 (control 127.0.0.1:7901) and wait for /health/ready.",
        "Run k6 crud_read.js and mutating_write.js together for $DurationSecs s against the node.",
        "POST /restart (X-Supervisor-Token) at 30 s and again at 70 s; each must answer 200.",
        "Wait for both k6 runs; fail (exit 1) if either reports http_req_failed above 0.",
        "Stop the supervisor (POST /stop) and write docs/evidence/drain-<date>-single.md."
    )
    rolling = @(
        "Check LOADTEST_ACK, the loadtest database name and seed.ps1's seed-info.json.",
        "Start two supervisors: node 1 on 0.0.0.0:7900 (control 7901), node 2 on 0.0.0.0:7910 (control 7911).",
        "Start nginx-loadtest (compose profile 'drain') on port 7990 over both nodes.",
        "Run k6 crud_read.js and mutating_write.js together for $DurationSecs s against nginx.",
        "At 30 s: POST /stop to node 1, wait for its supervisor to exit, start it again, wait until ready.",
        "Then the same for node 2.",
        "Wait for both k6 runs; fail (exit 1) if either reports http_req_failed above 0.",
        "Stop both supervisors and nginx; write docs/evidence/drain-<date>-rolling.md."
    )
}

if ($Plan) {
    Write-Host "Drain exercise, mode '$Mode' (AB7-T10):"
    $n = 1
    foreach ($step in $planSteps[$Mode]) {
        Write-Host ("  {0}. {1}" -f $n, $step)
        $n++
    }
    exit 0
}

. "$PSScriptRoot/common.ps1"
Assert-LoadtestSafety

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) {
    throw "loadtest/.generated/seed-info.json not found: run seed.ps1 first."
}
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json

if (-not (Test-Path $script:ServerExe)) {
    Write-Host "Building the release binary (first run only)..."
    & cargo build --release -p attome
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
}

# The control token, fresh per run, readable only by this run.
$token = -join ((1..40) | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 123) })
$tokenFile = Join-Path $script:GenDir "drain-token.txt"
[System.IO.File]::WriteAllText($tokenFile, $token, (New-Object System.Text.UTF8Encoding($false)))

$nodes = if ($Mode -eq "single") {
    @(@{ Port = 7900; Control = 7901 })
} else {
    @(@{ Port = 7900; Control = 7901 }, @{ Port = 7910; Control = 7911 })
}

function Start-DrainSupervisor {
    param([Parameter(Mandatory)][hashtable]$Node)
    $port = $Node.Port
    $cfgPath = Join-Path $script:GenDir "config-node-$port.json"
    $cfgJson = New-LoadtestConfig -Port $port -BootstrapAdminEmail $seed.admin_email
    [System.IO.File]::WriteAllText($cfgPath, $cfgJson, (New-Object System.Text.UTF8Encoding($false)))
    # The same environment Start-LoadtestNodes gives a node; the supervisor
    # passes it on to the server it starts.
    $env:APP_ENV = "debug"
    $env:CONFIG_FILE = $cfgPath
    $env:DATABASE_URL = "postgres://postgres:loadtest-throwaway-pw@$($script:LoadtestDbHost):$($script:LoadtestDbPort)/$($script:LoadtestDbName)?options=-c%20search_path%3Dattome_loadtest"
    $startArgs = @{
        FilePath               = $script:ServerExe
        ArgumentList           = @(
            "supervise", "--token-file", $tokenFile,
            "--listen", "0.0.0.0:$port", "--control-addr", "127.0.0.1:$($Node.Control)"
        )
        WorkingDirectory       = (Join-Path $script:RepoRoot "crates/apps/attome")
        RedirectStandardOutput = (Join-Path $script:LogDir "drain-$port.out.log")
        RedirectStandardError  = (Join-Path $script:LogDir "drain-$port.err.log")
        PassThru               = $true
    }
    if ($script:IsWindowsHost) { $startArgs.WindowStyle = "Hidden" }
    $Node.Process = Start-Process @startArgs
    Wait-NodeReady -Port $port -TimeoutSecs 180
    Write-Host "node on $port ready (supervisor pid $($Node.Process.Id))"
}

function Invoke-Supervisor {
    param([Parameter(Mandatory)][hashtable]$Node, [Parameter(Mandatory)][string]$Action)
    $uri = "http://127.0.0.1:$($Node.Control)/$Action"
    $resp = Invoke-WebRequest -Uri $uri -Method Post -UseBasicParsing -TimeoutSec 180 `
        -Headers @{ "X-Supervisor-Token" = $token }
    return [int]$resp.StatusCode
}

function Stop-DrainSupervisor {
    param([Parameter(Mandatory)][hashtable]$Node, [int]$TimeoutSecs = 120)
    if ($null -eq $Node.Process -or $Node.Process.HasExited) { return }
    try { [void](Invoke-Supervisor -Node $Node -Action "stop") } catch { }
    if (-not $Node.Process.WaitForExit($TimeoutSecs * 1000)) {
        Write-Warning "supervisor on $($Node.Port) did not exit after POST /stop; killing it"
        Stop-Process -Id $Node.Process.Id -Force -ErrorAction SilentlyContinue
    }
}

function Start-K6 {
    param([Parameter(Mandatory)][string]$Scenario, [Parameter(Mandatory)][string]$BaseUrl)
    $resultName = "drain-$Mode-$Scenario.json"
    $resultPath = Join-Path $script:ResultsDir $resultName
    if (Test-Path $resultPath) { Remove-Item $resultPath -Force }
    $k6EnvVars = @{
        BASE_URLS      = $BaseUrl
        TEST_EMAIL     = $seed.test_email
        TEST_PASSWORD  = $seed.test_password
        ADMIN_EMAIL    = $seed.admin_email
        ADMIN_PASSWORD = $seed.admin_password
        WIDE_ENTITY    = $seed.wide_entity
        BULK_ENTITY    = $seed.bulk_entity
        BULK_QUERY_ID  = $seed.bulk_query_id
        MUT_ENTITY     = $seed.mut_entity
        BULK_ROW_COUNT = $seed.bulk_row_count
        DURATION       = "${DurationSecs}s"
    }
    if ($Vus) { $k6EnvVars.VUS = $Vus }
    if ($Scenario -eq "mutating_write") {
        $idsPath = Join-Path $script:GenDir "mut-record-ids.json"
        [System.IO.File]::WriteAllText($idsPath, ($seed.mut_record_ids | ConvertTo-Json -Compress),
            (New-Object System.Text.UTF8Encoding($false)))
        $k6EnvVars.MUT_RECORD_IDS_FILE = if ($script:IsWindowsHost) { "/work/.generated/mut-record-ids.json" } else { $idsPath }
    }
    $envArgs = @()
    foreach ($kv in $k6EnvVars.GetEnumerator()) { $envArgs += @("-e", "$($kv.Key)=$($kv.Value)") }
    return Start-Job -ScriptBlock {
        param($isWindows, $loadtestDir, $scenario, $envArgs, $resultName, $resultPath)
        if ($isWindows) {
            & docker run --rm -v "${loadtestDir}:/work" @envArgs grafana/k6 run "/work/k6/$scenario.js" `
                --summary-export "/work/results/$resultName" 2>&1
        } else {
            & k6 run @envArgs (Join-Path $loadtestDir "k6/$scenario.js") --summary-export $resultPath 2>&1
        }
    } -ArgumentList $script:IsWindowsHost, $script:LoadtestDir, $Scenario, $envArgs, $resultName, $resultPath
}

function Read-K6Summary {
    param([Parameter(Mandatory)][string]$Scenario)
    $resultPath = Join-Path $script:ResultsDir "drain-$Mode-$Scenario.json"
    if (-not (Test-Path $resultPath)) {
        return [PSCustomObject]@{ scenario = $Scenario; requests = 0; failed = $null; rate = $null }
    }
    $summary = Get-Content $resultPath -Raw | ConvertFrom-Json
    $failedMetric = $summary.metrics.http_req_failed
    $rate = if ($null -ne $failedMetric.value) { $failedMetric.value }
            elseif ($null -ne $failedMetric.rate) { $failedMetric.rate }
            else { $null }
    $requests = [int]$summary.metrics.http_reqs.count
    $failed = if ($null -ne $failedMetric.passes) { [int]$failedMetric.passes }
              elseif ($null -ne $rate) { [int][Math]::Round($rate * $requests) }
              else { $null }
    return [PSCustomObject]@{ scenario = $Scenario; requests = $requests; failed = $failed; rate = $rate }
}

$events = New-Object System.Collections.Generic.List[string]
function Add-Event {
    param([string]$Text)
    $line = "{0:HH:mm:ss} {1}" -f (Get-Date), $Text
    $events.Add($line)
    Write-Host $line
}

$jobs = @()
$exitCode = 1
$started = Get-Date
try {
    foreach ($node in $nodes) { Start-DrainSupervisor -Node $node }
    if ($Mode -eq "rolling") {
        & docker compose -f (Join-Path $script:LoadtestDir "docker-compose.loadtest.yml") `
            --profile drain up -d nginx-loadtest
        if ($LASTEXITCODE -ne 0) { throw "docker compose up nginx-loadtest failed" }
        $lbPort = if ($env:LOADTEST_LB_PORT) { [int]$env:LOADTEST_LB_PORT } else { 7990 }
        $baseUrl = if ($script:IsWindowsHost) { "http://host.docker.internal:$lbPort" } else { "http://localhost:$lbPort" }
    } else {
        $baseUrl = if ($script:IsWindowsHost) { "http://host.docker.internal:7900" } else { "http://localhost:7900" }
    }

    $started = Get-Date
    Add-Event "load starts: crud_read + mutating_write for $DurationSecs s against $baseUrl"
    $jobs += Start-K6 -Scenario "crud_read" -BaseUrl $baseUrl
    $jobs += Start-K6 -Scenario "mutating_write" -BaseUrl $baseUrl

    $sleepUntil = {
        param([int]$Second)
        $wait = $Second - ((Get-Date) - $started).TotalSeconds
        if ($wait -gt 0) { Start-Sleep -Seconds ([int][Math]::Ceiling($wait)) }
    }

    if ($Mode -eq "single") {
        foreach ($at in @(30, 70)) {
            & $sleepUntil $at
            Add-Event "POST /restart (at ${at} s)"
            $status = Invoke-Supervisor -Node $nodes[0] -Action "restart"
            Add-Event "restart answered $status"
            if ($status -ne 200) { throw "POST /restart answered $status" }
        }
    } else {
        & $sleepUntil 30
        foreach ($node in $nodes) {
            Add-Event "POST /stop to the node on $($node.Port)"
            Stop-DrainSupervisor -Node $node
            Add-Event "node on $($node.Port) drained and stopped; starting it again"
            Start-DrainSupervisor -Node $node
            Add-Event "node on $($node.Port) ready"
        }
    }

    $jobs | Wait-Job -Timeout ($DurationSecs + 300) | Out-Null
    foreach ($job in $jobs) { Receive-Job -Job $job | Out-Host }
    Add-Event "load ends"

    $results = @((Read-K6Summary -Scenario "crud_read"), (Read-K6Summary -Scenario "mutating_write"))
    $results | Format-Table -AutoSize | Out-Host
    $missing = @($results | Where-Object { $_.requests -eq 0 -or $null -eq $_.rate })
    $failedAny = @($results | Where-Object { $null -ne $_.rate -and $_.rate -gt 0 })
    $exitCode = if ($missing.Count -gt 0 -or $failedAny.Count -gt 0) { 1 } else { 0 }

    # The evidence file (AB4 format: hardware, method, counts, failures).
    $cpu = if ($script:IsWindowsHost) {
        (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    } else {
        ((Get-Content /proc/cpuinfo | Where-Object { $_ -like "model name*" } | Select-Object -First 1) -split ":", 2)[1].Trim()
    }
    $memoryGb = if ($script:IsWindowsHost) {
        [Math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
    } else {
        [Math]::Round(([double](((Get-Content /proc/meminfo | Select-Object -First 1) -split "\s+")[1]) * 1KB) / 1GB, 1)
    }
    $commit = (& git -C $script:RepoRoot rev-parse --short HEAD) 2>$null
    $date = Get-Date -Format "yyyy-MM-dd"
    $verdict = if ($exitCode -eq 0) { "PASS: no failed request" } else { "FAIL" }
    $rows = $results | ForEach-Object { "| $($_.scenario) | $($_.requests) | $($_.failed) | $($_.rate) |" }
    $evidence = @(
        "# Drain under load, $Mode mode, $date",
        "",
        "AB7-T10, written by ``loadtest/scripts/run-drain-exercise.ps1 -Mode $Mode`` at commit ``$commit``.",
        "",
        "**Result: $verdict.**",
        "",
        "## Hardware",
        "",
        "- CPU: $cpu ($([Environment]::ProcessorCount) logical processors)",
        "- Memory: $memoryGb GB",
        "- OS: $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)",
        "",
        "## Method",
        "",
        ($planSteps[$Mode] | ForEach-Object { "- $_" }),
        "",
        "## Requests",
        "",
        "| Scenario | Requests | Failed | Failed rate |",
        "|---|---|---|---|",
        $rows,
        "",
        "## Timeline",
        "",
        ($events | ForEach-Object { "- $_" })
    ) | ForEach-Object { $_ }
    $evidenceDir = Join-Path $script:RepoRoot "docs/evidence"
    New-Item -ItemType Directory -Force -Path $evidenceDir | Out-Null
    $evidencePath = Join-Path $evidenceDir "drain-$date-$Mode.md"
    [System.IO.File]::WriteAllText($evidencePath, (($evidence -join "`n") + "`n"),
        (New-Object System.Text.UTF8Encoding($false)))
    Write-Host "evidence: $evidencePath"
} finally {
    foreach ($job in $jobs) {
        Stop-Job -Job $job -ErrorAction SilentlyContinue
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
    foreach ($node in $nodes) { Stop-DrainSupervisor -Node $node }
    if ($Mode -eq "rolling") {
        & docker compose -f (Join-Path $script:LoadtestDir "docker-compose.loadtest.yml") `
            --profile drain stop nginx-loadtest | Out-Null
    }
    Remove-Item $tokenFile -Force -ErrorAction SilentlyContinue
}

if ($exitCode -ne 0) {
    Write-Host "drain exercise FAILED: a request failed or a k6 run left no summary" -ForegroundColor Red
}
exit $exitCode
