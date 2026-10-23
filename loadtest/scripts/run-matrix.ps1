# P1.8d step 4 — runs every k6 scenario at N=1/4/12 app nodes and writes a
# raw-results JSON that Write-LoadtestReport (or a human) turns into
# document_v2/docs/LOADTEST-<date>.md. Requires seed.ps1 to have already run once
# (docker-compose.loadtest.yml's Postgres/Dragonfly keep the seeded data
# across node restarts — only the node processes themselves get recycled
# per N).
#
# k6 execution mode is OS-dependent (see common.ps1's $script:IsWindowsHost):
# on Windows/Docker Desktop, the `grafana/k6` container can't reach the
# host's `localhost` directly, so BASE_URLS uses `host.docker.internal` and
# k6 runs via `docker run`. On Linux (a dedicated host, or the
# loadtest-smoke.yml CI job) this script instead shells out to a native `k6`
# binary (must already be on PATH — CI installs it via the official apt repo)
# against plain `localhost`, since there's no container boundary to cross.
param(
    [int[]]$NodeCounts = @(1, 4, 12),
    [string[]]$Scenarios = @('auth', 'metadata_read', 'crud_read', 'list_query', 'mutating_write', 'notification_poll'),
    [string]$Vus = "",       # per-scenario override via env if empty, else applies to all
    [string]$Duration = "30s",
    # P1.8d step 5 — "pgbouncer" requires docker-compose.pgbouncer.yml's
    # pgbouncer-loadtest service already up (see loadtest/README.md).
    [ValidateSet("direct", "pgbouncer")]
    [string]$Topology = "direct",
    # P1.8d step 6 — re-run this same matrix with the P1.13 cutover path on,
    # to compare against the sync-path (chainer_enabled=false) baseline
    # recorded in document_v2/docs/LOADTEST-2026-07-19.md.
    [switch]$ChainerEnabled,
    # Distinguishes this run's result files from a prior run's (e.g.
    # "chainer", "pgbouncer") so re-runs under a different topology/chainer
    # setting don't silently overwrite the baseline matrix-summary.json.
    [string]$RunTag = "",
    # AA1-T3: the profile whose seed summary (results/seed-<profile>.json)
    # names the users production_mix.js logs in as.
    [string]$Profile = "solo",
    # AA1-T3: before each scenario, restart the nodes and empty the cache, and
    # run with no warm-up window. Default is warm: production_mix.js discards
    # its first 30 s.
    [switch]$Cold,
    # AA1-T4: the production-shaped run. Unless -Scenarios is passed (the
    # per-scenario matrix above), the script runs this k6 mix once per
    # concurrency level of -Profile (profiles.json), with the audit chainer on.
    [string]$Mix = "production_mix",
    # AA1-T4: run against a read replica (database.read_url). Needs the
    # scale-out recipe's replica compose stack, which this repository does
    # not ship yet, so a real run refuses; -Plan still lists the files.
    [switch]$Replica,
    # AA1-T4: print each planned level and its result file, then exit 0
    # without starting nodes or k6.
    [switch]$Plan
)
. "$PSScriptRoot/common.ps1"

if (-not $PSBoundParameters.ContainsKey('Scenarios')) {
    $profiles = Get-Content (Join-Path $script:LoadtestDir "profiles.json") -Raw | ConvertFrom-Json
    $profileInfo = $profiles.$Profile
    if ($null -eq $profileInfo -or $Profile -like "_*") {
        throw "Unknown profile '$Profile' — profiles.json has: " +
              (($profiles.PSObject.Properties.Name | Where-Object { $_ -notlike "_*" }) -join ", ")
    }
    if (-not (Test-Path (Join-Path $script:LoadtestDir "k6/$Mix.js"))) {
        throw "No k6 mix loadtest/k6/$Mix.js"
    }
    $target = if ($Replica) { "replica" } else { "primary" }
    $levels = @($profileInfo.concurrency_levels)
    $planned = foreach ($level in $levels) {
        [PSCustomObject]@{ level = [int]$level; file = "$Mix-$Profile-c$level-$target.json" }
    }
    if ($Plan) {
        foreach ($p in $planned) { Write-Host "c$($p.level) $target -> loadtest/results/$($p.file)" }
        exit 0
    }
    Assert-LoadtestSafety
    if ($Replica) {
        throw "-Replica needs the scale-out recipe's replica compose stack (a streaming replica " +
              "and database.read_url), which is not in this repository yet; run without -Replica."
    }

    $seedInfoPath = Join-Path $script:GenDir "seed-info.json"
    if (-not (Test-Path $seedInfoPath)) {
        throw "loadtest/.generated/seed-info.json not found — run seed.ps1 first."
    }
    $seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json
    $nodeCount = $NodeCounts[0]
    $rows = @()
    foreach ($p in $planned) {
        Write-Host ""
        Write-Host "=== $Mix c$($p.level) [$Profile, $target, $nodeCount node(s), chainer on] ==="
        $ports = Start-LoadtestNodes -Count $nodeCount -BootstrapAdminEmail $seed.admin_email `
            -Topology $Topology -ChainerEnabled
        # The run is production-shaped only if the nodes chain audit rows the
        # way a deployment does; a config that says otherwise is refused.
        foreach ($port in $ports) {
            $cfg = Get-Content (Join-Path $script:GenDir "config-node-$port.json") -Raw | ConvertFrom-Json
            if ($cfg.audit.chainer_enabled -ne $true) {
                Stop-LoadtestNodes
                throw "config-node-$port.json has audit.chainer_enabled = $($cfg.audit.chainer_enabled); " +
                      "the production-shaped run needs it true (New-LoadtestConfig -ChainerEnabled)."
            }
        }
        $baseUrls = if ($script:IsWindowsHost) {
            ($ports | ForEach-Object { "http://host.docker.internal:$_" }) -join ','
        } else {
            ($ports | ForEach-Object { "http://localhost:$_" }) -join ','
        }
        $resultPath = Join-Path $script:ResultsDir $p.file
        if (Test-Path $resultPath) { Remove-Item $resultPath -Force }
        $k6EnvVars = @{
            BASE_URLS      = $baseUrls
            TEST_EMAIL     = $seed.test_email
            TEST_PASSWORD  = $seed.test_password
            BULK_ENTITY    = $seed.bulk_entity
            BULK_QUERY_ID  = $seed.bulk_query_id
            BULK_ROW_COUNT = $seed.bulk_row_count
            DURATION       = $Duration
            WARMUP         = if ($Cold) { "0s" } else { "30s" }
            RATE           = $profileInfo.rated_rps
            VUS            = $p.level
        }
        $seedSummary = Join-Path $script:ResultsDir "seed-$Profile.json"
        if (Test-Path $seedSummary) {
            $k6EnvVars.SEED_FILE = if ($script:IsWindowsHost) { "/work/results/seed-$Profile.json" } else { $seedSummary }
        }

        # Peak connections: sampled every two seconds while k6 runs.
        $stopFile = Join-Path $script:GenDir "conn-sampler.stop"
        if (Test-Path $stopFile) { Remove-Item $stopFile -Force }
        $sampler = Start-Job -ArgumentList $stopFile -ScriptBlock {
            param($stop)
            $peak = 0
            while (-not (Test-Path $stop)) {
                $n = docker exec loadtest-postgres-loadtest-1 psql -U postgres -d attome_loadtest -t -A -c `
                    "SELECT count(*) FROM pg_stat_activity WHERE datname = 'attome_loadtest'" 2>$null
                if ("$n".Trim() -match '^\d+$' -and [int]"$n".Trim() -gt $peak) { $peak = [int]"$n".Trim() }
                Start-Sleep -Seconds 2
            }
            $peak
        }
        if ($script:IsWindowsHost) {
            $k6Env = @()
            foreach ($kv in $k6EnvVars.GetEnumerator()) { $k6Env += @("-e", "$($kv.Key)=$($kv.Value)") }
            & docker run --rm -v "$($script:LoadtestDir):/work" @k6Env grafana/k6 run `
                "/work/k6/$Mix.js" `
                --summary-trend-stats "avg,min,med,p(50),p(90),p(95),p(99),max" `
                --summary-export "/work/results/$($p.file)"
        } else {
            $k6Args = @()
            foreach ($kv in $k6EnvVars.GetEnumerator()) { $k6Args += @("-e", "$($kv.Key)=$($kv.Value)") }
            & k6 run @k6Args (Join-Path $script:LoadtestDir "k6/$Mix.js") `
                --summary-trend-stats "avg,min,med,p(50),p(90),p(95),p(99),max" `
                --summary-export $resultPath
        }
        New-Item -ItemType File -Path $stopFile -Force | Out-Null
        $peakConnections = Receive-Job -Job $sampler -Wait -AutoRemoveJob
        Remove-Item $stopFile -Force -ErrorAction SilentlyContinue

        if (Test-Path $resultPath) {
            $summary = Get-Content $resultPath -Raw | ConvertFrom-Json
            $trend = $summary.metrics.http_req_duration
            # The audit-lock symptom (writes stalling ~1.4 s behind the chain
            # lock) shows as the write class's max, not its percentiles.
            $write = $summary.metrics.'http_req_duration{op:write,phase:measure}'
            $failed = $summary.metrics.http_req_failed
            $backlogRaw = @(Get-AuditIngestBacklog)[0]
            $rows += [PSCustomObject]@{
                mix                  = $Mix
                profile              = $Profile
                level                = $p.level
                target               = $target
                file                 = $p.file
                p50_ms               = [Math]::Round($trend.'p(50)', 1)
                p95_ms               = [Math]::Round($trend.'p(95)', 1)
                p99_ms               = [Math]::Round($trend.'p(99)', 1)
                max_write_ms         = if ($null -ne $write) { [Math]::Round($write.max, 1) } else { $null }
                peak_pg_connections  = $peakConnections
                failed_requests      = if ($null -ne $failed) { $failed.passes } else { $null }
                audit_ingest_backlog = [int64]("$backlogRaw".Trim())
            }
            if ($null -ne $write -and $write.max -ge 1400) {
                Write-Warning "c$($p.level): a write took $([Math]::Round($write.max)) ms — the audit-lock symptom."
            }
        } else {
            Write-Warning "c$($p.level) produced no summary-export — check docker/k6 output above."
        }
        Stop-LoadtestNodes
    }
    $rows | Format-Table -AutoSize
    $summaryName = if ($RunTag) { "matrix-$Mix-$Profile-$target-$RunTag.json" } else { "matrix-$Mix-$Profile-$target.json" }
    $rows | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $script:ResultsDir $summaryName) -Encoding utf8
    Write-Host ""
    Write-Host "Matrix summary written to loadtest/results/$summaryName"
    exit 0
}

Assert-LoadtestSafety

$fileSuffix = if ($RunTag) { "-$RunTag" } else { "" }

$seedInfoPath = Join-Path $script:GenDir "seed-info.json"
if (-not (Test-Path $seedInfoPath)) {
    throw "loadtest/.generated/seed-info.json not found — run seed.ps1 first."
}
$seed = Get-Content $seedInfoPath -Raw | ConvertFrom-Json

$allResults = @()

foreach ($n in $NodeCounts) {
    Write-Host ""
    Write-Host "=== N=$n app node(s) [topology=$Topology chainer_enabled=$($ChainerEnabled.IsPresent)] ==="
    $ports = Start-LoadtestNodes -Count $n -BootstrapAdminEmail $seed.admin_email `
        -Topology $Topology -ChainerEnabled:$ChainerEnabled

    $baseUrls = if ($script:IsWindowsHost) {
        ($ports | ForEach-Object { "http://host.docker.internal:$_" }) -join ','
    } else {
        ($ports | ForEach-Object { "http://localhost:$_" }) -join ','
    }

    foreach ($scenario in $Scenarios) {
        Write-Host "--- $scenario (N=$n) ---"
        $resultPath = Join-Path $script:ResultsDir "$scenario-n$n$fileSuffix.json"
        if (Test-Path $resultPath) { Remove-Item $resultPath -Force }

        if ($Cold) {
            Stop-LoadtestNodes
            Clear-LoadtestCache
            $ports = Start-LoadtestNodes -Count $n -BootstrapAdminEmail $seed.admin_email `
                -Topology $Topology -ChainerEnabled:$ChainerEnabled
            $baseUrls = if ($script:IsWindowsHost) {
                ($ports | ForEach-Object { "http://host.docker.internal:$_" }) -join ','
            } else {
                ($ports | ForEach-Object { "http://localhost:$_" }) -join ','
            }
        }
        $k6EnvVars = @{
            BASE_URLS      = $baseUrls
            TEST_EMAIL     = $seed.test_email
            TEST_PASSWORD  = $seed.test_password
            ADMIN_EMAIL    = $seed.admin_email
            ADMIN_PASSWORD = $seed.admin_password
            WIDE_ENTITY    = $seed.wide_entity
            BULK_ENTITY    = $seed.bulk_entity
            BULK_QUERY_ID  = $seed.bulk_query_id
            MUT_ENTITY     = $seed.mut_entity
            BULK_ROW_COUNT = $seed.bulk_row_count
            DURATION       = $Duration
            WARMUP         = if ($Cold) { "0s" } else { "30s" }
        }
        $seedSummary = Join-Path $script:ResultsDir "seed-$Profile.json"
        if (Test-Path $seedSummary) {
            $k6EnvVars.SEED_FILE = if ($script:IsWindowsHost) { "/work/results/seed-$Profile.json" } else { $seedSummary }
        }
        if ($Vus) { $k6EnvVars.VUS = $Vus }
        if ($scenario -eq 'mutating_write') {
            # 300 UUIDs as a single -e value (~11.7KB) was getting mangled
            # somewhere in Windows/docker CLI argument passing (k6 saw
            # invalid JSON) -- write to a file inside the already-mounted
            # loadtest dir instead and pass just the short in-container path.
            $mutIdsPath = Join-Path $script:GenDir "mut-record-ids.json"
            $mutIdsJson = ($seed.mut_record_ids | ConvertTo-Json -Compress)
            [System.IO.File]::WriteAllText($mutIdsPath, $mutIdsJson, (New-Object System.Text.UTF8Encoding($false)))
            $k6EnvVars.MUT_RECORD_IDS_FILE = if ($script:IsWindowsHost) { "/work/.generated/mut-record-ids.json" } else { $mutIdsPath }
        }

        if ($script:IsWindowsHost) {
            $k6Env = @()
            foreach ($kv in $k6EnvVars.GetEnumerator()) { $k6Env += @("-e", "$($kv.Key)=$($kv.Value)") }
            & docker run --rm -v "$($script:LoadtestDir):/work" @k6Env grafana/k6 run `
                "/work/k6/$scenario.js" `
                --summary-trend-stats "avg,min,med,p(50),p(90),p(95),p(99),max" `
                --summary-export "/work/results/$scenario-n$n$fileSuffix.json"
        } else {
            $k6Args = @()
            foreach ($kv in $k6EnvVars.GetEnumerator()) { $k6Args += @("-e", "$($kv.Key)=$($kv.Value)") }
            & k6 run @k6Args (Join-Path $script:LoadtestDir "k6/$scenario.js") `
                --summary-trend-stats "avg,min,med,p(50),p(90),p(95),p(99),max" `
                --summary-export $resultPath
        }

        if (Test-Path $resultPath) {
            $summary = Get-Content $resultPath -Raw | ConvertFrom-Json
            # This k6 image's --summary-export is flat (metrics.http_req_duration.'p(50)'
            # directly), not the older nested metrics.*.values shape docs elsewhere assume.
            $trend = $summary.metrics.http_req_duration
            # failed_rate/checks_failed are recorded per row, not left to a
            # human reading the k6 console output: a scenario that 403s or 503s
            # every request still produces perfectly respectable percentiles
            # (they are the latency of the rejection), so a summary without the
            # failure rate next to them can look like a passing run when it is
            # measuring nothing. TODO-014's pre-run pass — the CSRF regression
            # it fixed would have been invisible in this file otherwise.
            $failed = $summary.metrics.http_req_failed
            $checks = $summary.metrics.checks
            # Field name, measured not guessed (2026-08-12 rehearsal): this k6
            # image exports a Rate metric as {passes, fails, value} — `value`
            # is the 0..1 rate, and there is no `rate` key at all. Reading
            # `.rate` yields $null, which [Math]::Round turns into a perfectly
            # innocent-looking 0.0 — a false clean bill of health, the exact
            # failure this column was added to prevent. `.rate` stays as a
            # fallback for a k6 version that does emit it; a metric with
            # neither records $null and warns rather than silently reporting 0.
            #
            # For http_req_failed specifically, k6's Rate counts a FAILED
            # request as a "pass" of the predicate, so `passes` is the failed-
            # request count — recorded raw alongside the rate because an
            # absolute count can't be misread the way a rounded 0.0 can.
            $failedRate = $null
            if ($null -ne $failed) {
                $rawRate = if ($null -ne $failed.value) { $failed.value } else { $failed.rate }
                if ($null -ne $rawRate) {
                    $failedRate = [Math]::Round([double]$rawRate, 4)
                } else {
                    Write-Warning "$scenario (N=$n): k6 summary has http_req_failed but neither .value nor .rate — failure rate NOT captured for this row."
                }
            }
            $row = [PSCustomObject]@{
                scenario         = $scenario
                nodes            = $n
                p50_ms           = [Math]::Round($trend.'p(50)', 1)
                p90_ms           = [Math]::Round($trend.'p(90)', 1)
                p99_ms           = [Math]::Round($trend.'p(99)', 1)
                max_ms           = [Math]::Round($trend.max, 1)
                requests         = $summary.metrics.http_reqs.count
                failed_rate      = $failedRate
                failed_requests  = if ($null -ne $failed) { $failed.passes } else { $null }
                checks_failed    = if ($null -ne $checks) { $checks.fails } else { $null }
            }
            if ($ChainerEnabled) {
                # Sampled after the window, while the load has just stopped: a
                # backlog that is still large here (vs. the drain the chainer
                # does within a poll interval or two) is the signal that the
                # cutover path did not keep up at this VU count.
                # psql -t -A hands back text; cast so the summary JSON holds a
                # number a reader can compare across rows, not "981".
                $backlogRaw = @(Get-AuditIngestBacklog)[0]
                $row | Add-Member -NotePropertyName audit_ingest_backlog `
                    -NotePropertyValue ([int64]("$backlogRaw".Trim()))
            }
            # Per SLO class (AA13-T6): each scenario tags its requests with
            # `slo_class` and declares thresholds on that submetric, so the
            # export carries `http_req_duration{slo_class:S<n>}` per class.
            # `attome slo report` reads these; a class with no entry is
            # reported as not measured, never as met.
            $classes = [ordered]@{}
            foreach ($prop in $summary.metrics.PSObject.Properties) {
                if ($prop.Name -match '^http_req_duration\{slo_class:(S\d+)\}$') {
                    $classes[$Matches[1]] = [PSCustomObject]@{
                        p50_ms = [Math]::Round($prop.Value.'p(50)', 1)
                        p95_ms = [Math]::Round($prop.Value.'p(95)', 1)
                        p99_ms = [Math]::Round($prop.Value.'p(99)', 1)
                    }
                }
            }
            $row | Add-Member -NotePropertyName classes -NotePropertyValue ([PSCustomObject]$classes)
            $allResults += $row
            if ($row.failed_requests -gt 0) {
                Write-Warning "$scenario (N=$n): $($row.failed_requests) failed request(s), rate $($row.failed_rate) — this run is not clean evidence."
            }
        } else {
            Write-Warning "$scenario (N=$n) produced no summary-export — check docker/k6 output above."
        }
    }

    Stop-LoadtestNodes
}

$allResults | Format-Table -AutoSize
$summaryName = "matrix-summary$fileSuffix.json"
$allResults | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $script:ResultsDir $summaryName) -Encoding utf8
Write-Host ""
Write-Host "Full matrix written to loadtest/results/$summaryName"
