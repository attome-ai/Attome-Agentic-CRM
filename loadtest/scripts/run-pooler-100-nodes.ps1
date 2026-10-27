# AA8-T1 — 100 simulated app nodes against the transaction-pooling
# pgbouncer: does Postgres's own backend count stay near the pooler's pool
# while the clients' latency holds?
#
# A real app node is a full server process; 100 of them do not fit one
# machine. What a node costs Postgres is its pool of connections, so a
# simulated node here is that pool: pgbench runs NodeCount x PoolSize
# clients (each node's `database.connection_number`) through pgbouncer, with
# a read-heavy mix like the app's (point reads, short writes), and the script
# samples Postgres's backend count while it runs. The same run against
# Postgres directly is the comparison: there every client is a backend.
#
# Code only on the machine that wrote it (no Docker daemon there); run it on
# the build machine and keep the result next to LOADTEST-2026-07-21.md.
#
# Usage:
#   $env:LOADTEST_ACK = "yes"
#   docker compose -f docker-compose.loadtest.yml -f docker-compose.pgbouncer.yml up -d postgres-loadtest pgbouncer-loadtest
#   ./scripts/run-pooler-100-nodes.ps1                      # 100 nodes x 8, 60 s, both topologies
#   ./scripts/run-pooler-100-nodes.ps1 -NodeCount 50 -PoolSize 16
param(
    [ValidateRange(1, 200)][int]$NodeCount = 100,
    [ValidateRange(1, 64)][int]$PoolSize = 8,
    [ValidateRange(10, 3600)][int]$Seconds = 60,
    [ValidateSet('pgbouncer', 'direct', 'both')][string]$Topology = 'both'
)
. "$PSScriptRoot/common.ps1"
Assert-LoadtestSafety

$clients = $NodeCount * $PoolSize
$container = 'loadtest-postgres-loadtest-1'
$resultsDir = Join-Path $script:GenDir 'results'
New-Item -ItemType Directory -Force -Path $resultsDir | Out-Null

# The mix: 9 point reads for each short write, on pgbench's own tables, so the
# test needs no seeded app schema.
$mix = @'
\set aid random(1, 100000 * :scale)
\set delta random(-5000, 5000)
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
UPDATE pgbench_accounts SET abalance = abalance + :delta WHERE aid = :aid;
'@
$mix | docker exec -i $container sh -c 'cat > /tmp/aa8-mix.sql'

Write-Host "initialising pgbench tables (scale 10)..."
docker exec $container pgbench -i -s 10 -q -U postgres attome_loadtest | Out-Null

function Invoke-Pass([string]$name, [string]$host_, [int]$port, [string]$db) {
    Write-Host "== $name : $NodeCount nodes x $PoolSize = $clients clients for $Seconds s"
    $out = Join-Path $resultsDir "aa8-pooler-$name.txt"
    # pgbench in the background inside the container; sample backends meanwhile.
    $job = Start-Job -ScriptBlock {
        param($c, $h, $p, $n, $s, $d)
        docker exec -e PGPASSWORD=loadtest-throwaway-pw $c pgbench -h $h -p $p -U postgres `
            -c $n -j 16 -T $s -n -M simple -P 10 -r -f /tmp/aa8-mix.sql $d 2>&1
    } -ArgumentList $container, $host_, $port, $clients, $Seconds, $db
    $samples = [System.Collections.Generic.List[int]]::new()
    while ($job.State -eq 'Running') {
        $n = Get-PgLoadtestConnectionCount
        if ($n -match '^\d+$') { $samples.Add([int]$n) }
        Start-Sleep -Seconds 5
    }
    $text = Receive-Job $job -Wait -AutoRemoveJob
    $text | Set-Content -Encoding utf8 $out
    $tps = ($text | Select-String -Pattern 'tps = ([0-9.]+)' | Select-Object -Last 1).Matches.Groups[1].Value
    $lat = ($text | Select-String -Pattern 'latency average = ([0-9.]+) ms').Matches.Groups[1].Value
    $failed = ($text | Select-String -Pattern 'number of failed transactions: (\d+)').Matches.Groups[1].Value
    [pscustomobject]@{
        topology        = $name
        clients         = $clients
        tps             = [double]$tps
        latency_avg_ms  = [double]$lat
        failed          = if ($failed) { [int]$failed } else { 0 }
        pg_backends_max = if ($samples.Count) { ($samples | Measure-Object -Maximum).Maximum } else { $null }
        pg_backends_avg = if ($samples.Count) { [math]::Round(($samples | Measure-Object -Average).Average, 1) } else { $null }
    }
}

$rows = @()
# Inside the compose network pgbouncer listens on 6432 (its pooled alias of
# the database, pgbouncer.ini) and Postgres on 5432.
if ($Topology -in 'pgbouncer', 'both') { $rows += Invoke-Pass 'pgbouncer' 'pgbouncer-loadtest' 6432 'attome_loadtest_pooled' }
if ($Topology -in 'direct', 'both') {
    if ($clients -gt 900) {
        Write-Warning "direct: $clients clients exceed Postgres's max_connections; expect connection failures (that is the point of the pooler)."
    }
    $rows += Invoke-Pass 'direct' 'localhost' 5432 'attome_loadtest'
}

$summary = Join-Path $resultsDir 'aa8-pooler-summary.json'
$rows | ConvertTo-Json | Set-Content -Encoding utf8 $summary
$rows | Format-Table -AutoSize
Write-Host "wrote $summary"
