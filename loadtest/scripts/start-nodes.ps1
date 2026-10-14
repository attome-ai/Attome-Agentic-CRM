# Starts N attome-website server processes against the isolated loadtest
# Postgres/Dragonfly (docker-compose.loadtest.yml must already be up).
# Ports are sequential from 7900. Usage:
#   $env:LOADTEST_ACK = "yes"
#   ./start-nodes.ps1 -Count 4
param(
    [int]$Count = 1,
    [string]$BootstrapAdminEmail = "",
    [ValidateSet("direct", "pgbouncer")]
    [string]$Topology = "direct",
    [switch]$ChainerEnabled
)
. "$PSScriptRoot/common.ps1"
Start-LoadtestNodes -Count $Count -BootstrapAdminEmail $BootstrapAdminEmail -Topology $Topology -ChainerEnabled:$ChainerEnabled
