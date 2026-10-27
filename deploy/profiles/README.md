# Deployment profiles

`solo`, `team`, `ha` and `scale` (roadmap U2-T1): each lists its services
(`server`, `worker`, `postgres`, `pgbouncer`, `cache`) with replicas, CPU
(percent of one core) and memory, and the configuration settings it needs.
`attome cluster plan` prints the files a profile needs for one target:

    attome cluster plan --profile solo                    # systemd units + config overlay
    attome cluster plan --profile ha --target compose     # docker-compose.yml
    attome cluster plan --profile scale --target helm     # values for deploy/helm/attome

The files are built into the binary, so the command works anywhere. One server
with PostgreSQL (`solo`) is the normal install; `ha` and `scale` are opt-in
(V2-D100). The sizes are proposals from `loadtest/profiles.json`'s reference
machines until the AA2 runs measure them.
