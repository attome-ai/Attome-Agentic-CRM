# Standby region

An optional second Patroni cluster in another region (AB2-T9). It holds a full, continuously
streamed copy of the database and takes no writes until it is promoted. Reliability features are
opt-in (V2-D100): a deployment without `ops.standby_region` has none of this.

## Setting it up

1. Pick the region and add it to `residency.allowed_regions`. A standby holds every record, so boot
   refuses an `ops.standby_region` whose `region_code` is not listed there, and with no list at all.
   The residency check counts the standby as one more data-holding component.
2. Start the standby's database nodes with `patroni-standby.yml.example`, its `standby_cluster`
   pointing at the main cluster's HAProxy write port, and the replication user's password in
   `PATRONI_REPLICATION_PASSWORD`.
3. Configure the standby in the main deployment's configuration:

   ```json
   "ops": {
     "standby_region": {
       "region_code": "sa-jeddah",
       "patroni_api_url": "http://dr-db1:8008",
       "scope": "attome-dr"
     }
   }
   ```

4. Keep the application servers of the standby region stopped, or pointed at the main region.

## When to promote

Only when the main region is lost: its database cannot be reached and will not be back within the
recovery time you have agreed. **Never while the main region is reachable.** Two clusters taking
writes at once split the data, and the writes of one side are lost when you join them again. Before
promoting, make sure the main cluster is down or fenced (its HAProxy stopped, its nodes powered off),
and write down the time: everything the main region committed after the standby's last streamed
change is not in the standby.

```bash
attome drill standby-promote --cluster attome-dr --confirm attome-dr
```

The command refuses unless both names are the same, are the configured `ops.standby_region.scope`,
and are the scope the standby's own Patroni reports. It then removes `standby_cluster` from the
standby's dynamic configuration; its leader stops following the main region and takes writes once
elected. Point the application servers (`database.host`) at the standby region's HAProxy and start
them.

## Failing back

The old main region cannot simply be started again: its data has diverged from the promoted one.

1. Keep the old main cluster's nodes stopped.
2. Rebuild them as a standby of the new main: give them a Patroni configuration like
   `patroni-standby.yml.example` whose `standby_cluster` points at the new main's HAProxy, clear or
   `pg_rewind` their data directories, and let them catch up.
3. In a quiet window, stop the application, promote the old main back with
   `attome drill standby-promote` run against it (its `ops.standby_region` naming it), point the
   application at it, and rebuild the other side as the standby again.
4. Record the failover and failback times and any data the gap lost in the incident's evidence.
