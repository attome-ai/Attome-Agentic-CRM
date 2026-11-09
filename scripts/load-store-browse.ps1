<#
.SYNOPSIS
  F8-T13: browse load on the guest catalogue of a test deployment.

.DESCRIPTION
  Requests GET {BaseUrl}/{Keyword}/api/v1/shop/guest/catalogue `-Requests` times
  (10,000 by default) with `-Clients` concurrent clients (100 by default) and
  prints one line, `p95_ms=<value>`. A failed request (any status but 2xx, or a
  timeout) is counted and printed as `failed=<n>`; the script exits 1 when any
  failed.

  Run it against a throwaway test deployment with `commerce.enabled` and
  `commerce.guest_account` set, never the shared dev database. It measures one
  machine's browse path; it is not a peak-sale capacity claim, so do not quote
  it as one.

.EXAMPLE
  powershell -File scripts/load-store-browse.ps1 -BaseUrl http://127.0.0.1:7865 -Keyword shop
#>
param(
    [Parameter(Mandatory = $true)][string]$BaseUrl,
    [string]$Keyword = 'shop',
    [int]$Requests = 10000,
    [int]$Clients = 100
)

$ErrorActionPreference = 'Stop'
if ($Requests -lt 1 -or $Clients -lt 1) { throw 'Requests and Clients must be at least 1' }
$Clients = [Math]::Min($Clients, $Requests)
$url = '{0}/{1}/api/v1/shop/guest/catalogue' -f $BaseUrl.TrimEnd('/'), $Keyword.Trim('/')

# Each client takes its share (the remainder goes to the first clients) and
# returns one [latency ms, ok] pair per request.
$share = [Math]::Floor($Requests / $Clients)
$extra = $Requests % $Clients
$work = {
    param($url, $count)
    Add-Type -AssemblyName System.Net.Http
    $http = [System.Net.Http.HttpClient]::new()
    $http.Timeout = [TimeSpan]::FromSeconds(30)
    $out = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $count; $i++) {
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $ok = $false
        try {
            $response = $http.GetAsync($url).GetAwaiter().GetResult()
            $ok = $response.IsSuccessStatusCode
            $response.Dispose()
        }
        catch { $ok = $false }
        $watch.Stop()
        $out.Add(@($watch.Elapsed.TotalMilliseconds, $ok))
    }
    $http.Dispose()
    , $out
}

$jobs = for ($c = 0; $c -lt $Clients; $c++) {
    $n = $share + $(if ($c -lt $extra) { 1 } else { 0 })
    Start-Job -ScriptBlock $work -ArgumentList $url, $n
}
$results = $jobs | Wait-Job | Receive-Job
$jobs | Remove-Job -Force

$latencies = New-Object 'System.Collections.Generic.List[double]'
$failed = 0
foreach ($batch in $results) {
    foreach ($pair in $batch) {
        $latencies.Add([double]$pair[0])
        if (-not $pair[1]) { $failed++ }
    }
}
if ($latencies.Count -eq 0) { throw 'no request ran' }
$sorted = $latencies | Sort-Object
$index = [Math]::Min($sorted.Count - 1, [int][Math]::Ceiling($sorted.Count * 0.95) - 1)
Write-Output ([string]::Format([Globalization.CultureInfo]::InvariantCulture, 'p95_ms={0:F1}', $sorted[$index]))
if ($failed -gt 0) {
    Write-Output ('failed={0}' -f $failed)
    exit 1
}
