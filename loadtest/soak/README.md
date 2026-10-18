# Soak

`soak.ps1` holds the production-shaped mix (`../k6/production_mix.js`) at 30% of a profile's rated load
(`rated_rps` in `../profiles.json`, a proposal until AA2 measures it) for a long time, 24 hours by
default, against one node set that is never restarted. Every 5 minutes it writes the nodes' resident
memory, the Postgres connection count and p95 per operation class to `../results/soak-<date>.csv`.

At the end it compares the first hour with the last hour (the first and last third of the windows for a
run under two hours). The run **fails** when memory grew more than 15% or any class's p95 grew more than
10%. Either is a leak or a slow drift that a short benchmark cannot see.

```powershell
$env:LOADTEST_ACK = "yes"
docker compose -f loadtest/docker-compose.loadtest.yml up -d
./loadtest/scripts/seed.ps1 -Profile solo
pwsh -File loadtest/soak/soak.ps1 -Profile solo                       # 24 hours
pwsh -File loadtest/soak/soak.ps1 -Profile solo -DurationMinutes 10   # a quick check of the script
```

Options: `-LoadFraction` (0.3), `-WindowMinutes` (5), `-NodeCount` (1), `-MaxRssGrowth` (0.15) and
`-MaxP95Growth` (0.10). Run the Solo and Team profiles before a release; a FAIL names what drifted.
