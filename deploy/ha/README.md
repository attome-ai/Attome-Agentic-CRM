# Database high availability

Optional (V2-D100): one database server is the normal case, and nothing here is needed for it.

## Main cluster

`patroni.yml.example` runs the main database as a three-node Patroni cluster on a three-member
etcd, behind HAProxy (write port to the leader, read port to the replicas). It is set for no data
loss on failover:

- **Synchronous replication** (`synchronous_mode: true`, one synchronous replica): a commit returns
  only once a replica has it. With `synchronous_mode_strict: false` the primary keeps taking writes
  when its only replica is down; a failover in that window can lose what it committed alone. Set
  it to true to refuse writes then instead.
- **Caught-up-only promotion** (`maximum_lag_on_failover: 0`): a replica that is behind is never
  promoted.
- **Watchdog fencing** (`watchdog.mode: required`): a node takes the leader lock only with a
  working watchdog, which resets a hung primary before another is promoted. Without a hardware
  watchdog, load `softdog` (`modprobe softdog`) and give the Patroni user `/dev/watchdog`.
- **pg_rewind** (`use_pg_rewind: true`, `wal_log_hints` on, data checksums at init): a former
  primary rejoins as a replica without a full copy; a failed rewind keeps its data directory for
  you to look at (`remove_data_directory_on_rewind_failure: false`).

Point the deployment's `database` section at HAProxy's write port. The `attome drill` commands
exercise failover; record the recovery point they measure.

## Failover drill

`attome drill failover` proves the cluster fails over without losing acknowledged writes. Run it
against a rig, never the deployment's own database (the command refuses that one):

```
attome drill failover --scenario leader --confirm leader --key drill-signing.key   --database-url postgres://drill:...@haproxy:5000/drill   --member-url postgres://drill:...@pg1:5432/drill --member-url ...   --patroni http://pg1:8008 --patroni http://pg2:8008
```

It writes to `drill_failover_probe` every 50 ms, asks Patroni (`POST /failover`) to move the leader to
a synchronous replica, and records how long writes failed, how many acknowledged writes are missing
afterwards and whether more than one member answers as primary. `--scenario router --service <name>`
stops a local router service instead (and starts it again), and `--scenario redis --sentinel <host:port>
--sentinel-service <name> --redis-member <host:port> ...` fails Redis over through its sentinel. The
signed evidence lands in `drill-evidence/failover-drill-evidence-<date>-<scenario>.json`; check it with
`attome drill verify`. It passes with no write lost, no split brain and writes back within 30 seconds.

## Chaos faults

`attome drill chaos run --fault <name> [--duration <s>]` injects one fault of the catalogue on a test
rig and always undoes it, when the time is up, on Ctrl+C, or if anything fails part way. It uses the
host's own tools: the service manager for `process-kill`, `postgres-restart`, `redis-down` and
`file-store-down` (`--service`, `--pg-service`, `--redis-service`, `--store-service`), `systemctl kill
-s STOP/CONT` for the pauses (Linux only), a file in `--fill-dir` for `disk-fill`, a swapped
`--cert-path` for `cert-expired`, 10,000 no-op jobs into `--database-url`'s queue for `queue-flood`,
and `tc netem` on `--iface` for `network-delay` (Linux, with `--allow-net-admin`). For `ai-slow`,
`ai-failing` and `email-down`, boot the target with the lines `--fake-endpoints` prints, then run the
fault. A deployment whose profile is `production` is refused.

Add `--steady-url <address> --api-key <public:secret>` to measure the steady state around the fault: ten
workers read a list page of `--steady-entity` (`account`) throughout; the run prints requests, error rate
and p95 before, during and after; during the fault it stops itself after three 10-second windows past
`--max-error-rate` (0.05) or `--max-p95-ms` (2000), and every 5 seconds checks that a reused idempotency
key with a different body is refused. With `--database-url` it verifies the audit chain afterwards. Any
of these failing makes the run fail.

### Production game days

A production deployment refuses chaos runs. To run one on purpose, turn on
`ops.chaos.production_game_days` (off by default) and ask for the run:
`POST /api/v1/ops/chaos/requests` with `{"fault", "duration_secs", "reason"}` (`ops.chaos.run`;
at most `ops.chaos.max_duration_secs`, 300 by default). A second member of the Operations role
approves it in the approvals inbox; the requester never can. Then, on the server:
`attome drill chaos run --fault <name> --duration <s> --production --approval-id <id>`. The command
checks the approval is for that fault and within the approved duration, and claims it, so one
approval allows one run.

## Standby region

`patroni-standby.yml.example` and [README-standby.md](README-standby.md): a second cluster in
another region that streams from the main one and takes no writes until it is promoted.
