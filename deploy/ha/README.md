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

## Standby region

`patroni-standby.yml.example` and [README-standby.md](README-standby.md): a second cluster in
another region that streams from the main one and takes no writes until it is promoted.
