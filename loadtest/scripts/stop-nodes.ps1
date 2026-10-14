# Stops whatever node processes start-nodes.ps1/seed.ps1/run-matrix.ps1 launched.
. "$PSScriptRoot/common.ps1"
Stop-LoadtestNodes
Write-Host "Loadtest node processes stopped."
