# Recovery drills

A drill proves a recovery path works: it breaks or restores something on a copy, measures it, and
writes signed evidence. The deployment keeps the evidence, shows how fresh each kind is, and gives an
auditor the pack for a period. Nothing in the server runs a drill; a drill host does.

## The drill host

A machine that can reach the copy it drills against (a restore target, a high-availability rig, a
test deployment), with the `attome` binary of the release under test. It holds the drill signing key
and runs the drills:

| Drill | Command |
|---|---|
| Restore | `attome drill restore --server-binary <path> --expected-digest <sha256> --api-key-file <file> --key <file> --out <dir> [--archive latest\|<name>] [--port 7999]` (see below). `attome backup drill` is the lighter monthly check: it restores the newest backup into a throwaway database and records an unsigned result in the backup folder's `drills.jsonl` (see [backup](backup.md)) |
| Failover | `attome drill failover --scenario <leader\|router\|redis> --confirm <scenario> --key <file> --out <dir> ...` |
| Chaos | `attome drill chaos run --fault <name> ...` for one fault, `attome drill chaos suite --key <file> --out <dir> ...` for every fault in turn, one report each |
| Readiness | `attome drill readiness` (the preflight checks, the signing key is readable, room for a restore) |

A chaos run refuses a production deployment unless it is an approved game day
(`ops.chaos.production_game_days`, a second person's approval of `POST /api/v1/ops/chaos/requests`);
the suite never runs against production.

## The restore drill

`attome drill restore` runs on the deployment's own machine (it needs the backup folder and the
database server's credentials from the configuration) and leaves nothing behind:

1. It restores the backup (`--archive`, the newest by default) into a throwaway database
   `attome_drill_<time>` on the same PostgreSQL server. The time this takes is the database's
   recovery time.
2. The recovery point is how far the copy's newest audit row is behind the live deployment's.
3. The SHA-256 of `--server-binary` must be `--expected-digest` (the release's published digest).
   On the copy it also checks the files, the sealed values and the search index: up to 200 recent
   clean uploads' recorded SHA-256 against the backup's own file copies (never the live file store;
   files the backup holds that no record names are counted as orphans, not failures), every sealed
   attribute value it samples opened with the deployment's key ring (counts only), and every search
   document of the most indexed entity naming a record of the copy. The evidence's data size is
   the copy's `pg_database_size`.
4. It starts that binary against the copy on `--port` with a throwaway configuration made from the
   deployment's own file: the copy's database, the cache in process memory (the live Redis is never
   touched), no job worker or scheduler, no email and no backup, so the copy sends nothing. The time
   to `/health/ready` (up to 300 s) is the application's recovery time.
5. It runs `verify-audit-chain` against the copy and, with the key in `--api-key-file` (a read-only
   key of the live deployment, which the copy holds too), reads a first page of five entities.
6. It stops the server, drops the database and deletes the configuration (`scratch_destroyed`), and
   writes `restore-drill-evidence-<date>.json`, signed with `--key`, into `--out`. The evidence
   holds checks, counts and times, never record contents.

Exit 0 when every check passed, 3 when one failed. pgBackRest restores are not part of it (v2 backs
up with `pg_dump`).

## Recovering after a disaster

`attome drill recover` is part 1 of rebuilding a deployment on a new host: it never starts without a
second person, either an approved disaster approval (`--approval-id <id> --base-url <url>
--api-key-file <file>`, the request made under **Ops → Recovery**) or, when the deployment cannot
answer, two different people named with `--offline-two-person <name1>,<name2>`, both kept in the
record. It loads the configuration with every secret resolved from the configured secret sources
and key service (a failure names the placeholder, never a value), checks the SHA-256 of
`--server-binary` against `--expected-digest`, and restores the backup (`--archive`, the newest by
default) into the configured database, which must not exist yet, or into a new database named with
`--side-copy <name>`, never the configured one. It writes `recover-state.json` (who approved, the
archive, the target, the database's recovery time, the digest; no secret) into `--out` for part 2.
v2 backs up with `pg_dump`, so the newest archive is the recovery point; there is no point-in-time
target.

## The chaos faults

Each fault of the catalogue (`attome_release::chaos::CATALOGUE`), what a correct deployment does
under it, and how the run undoes it. A run always undoes its fault: when its time is up, on Ctrl+C,
and when injecting it failed part way.

| Fault | A correct deployment | Undo | Default length |
|---|---|---|---|
| `process-kill` | The killed node's requests fail over to the others; durable jobs it held are retried by another node after their lease; no write is half done. | Start the process again. | 60 s |
| `postgres-restart` | Requests during the restart answer 503 db_unavailable (GET and idempotent requests are retried inside the server's window); the pool reconnects without a server restart. | Nothing: Postgres comes back by itself. | 30 s |
| `postgres-pause` | Requests time out at their route deadline with 504, the pool does not grow without bound, and readiness turns not ready until Postgres answers. | Unpause the Postgres container. | 30 s |
| `disk-fill` | Uploads refuse with a clear storage error, logs keep rotating, and the disk alert fires; nothing already stored is lost. | Delete the fill file. | 120 s |
| `redis-down` | Rate limits and replay checks refuse with 503 (they fail closed); records still save when AB5 is built, otherwise the server reports not ready. | Start Redis again. | 60 s |
| `redis-pause` | Cache reads time out within the Redis timeout and fall back to Postgres; security checks fail closed; no request hangs. | Unpause the Redis container. | 30 s |
| `file-store-down` | Uploads and downloads answer 503 with Retry-After; records without files still save; the file-store dependency shows down. | Start the object store again. | 60 s |
| `ai-slow` | Assistant turns stop at their deadline with a clear message; nothing else slows down; the AI breaker opens after repeated timeouts. | Remove the added latency. | 120 s (needs `--allow-net-admin`) |
| `ai-failing` | The fallback model answers when one is set, otherwise the assistant says it is unavailable; records and flows are unaffected. | Point the provider back at the real endpoint. | 120 s |
| `email-down` | Emails stay in the outbox and are sent after the server returns; the business change that wrote them is not rolled back. | Start the mail server again. | 120 s |
| `cert-expired` | Outbound calls to the expired endpoint fail the TLS check and are not sent in clear; the certificate alert fires. | Restore the valid certificate. | 60 s |
| `queue-flood` | Interactive requests keep their latency while background jobs drain at the throttled pace; the backlog alert fires and clears. | Let the flood drain or cancel the flood jobs. | 300 s |
| `network-delay` | Requests slow by the added delay but stay within their deadlines or fail at them; no retry storm (retries keep their budget). | Remove the netem delay. | 120 s (needs `--allow-net-admin`) |

Before a release, `attome release --check --chaos` runs the suite against the release candidate
on a rig (see [cutting a release](release.md)).

## Evidence

Each report is `attome-evidence/v1`, described by
[`schemas/attome-evidence-v1.schema.json`](../schemas/attome-evidence-v1.schema.json): the kind
(`restore`, `failover`, `chaos`, `upgrade`, `secrets`, `recovery`, `drain`), when it ran, the platform
version, each check with its result (`pass`, `fail`, `skipped`), the recovery point and time where
they apply, `overall_ok` (every check passed, and for a restore the data and provenance too) and the
kind's own `extra` (a chaos report names its `fault`). The signature covers the report's canonical
bytes.

`attome drill verify <report.json> [--public-key <file>]` checks a report's signature. Uploading it
(`POST /api/v1/ops/drills/evidence`, `ops.drill.run`) checks the signature against
`ops.drill_public_keys`, stores it once (keyed by its hash) and moves the kind's schedule on.
`GET /api/v1/ops/drills` lists the runs (`?kind=` for one kind), `GET /api/v1/ops/drills/freshness`
says whether each kind is fresh, stale, failed or never run, and
`GET /api/v1/ops/drills/auditor-pack?from=&to=` (`ops.auditor.read`) downloads a period's evidence.
The Recovery drills page shows the same, and agents read it through `ops.drill_freshness`,
`ops.drill_evidence` and `ops.chaos_results`.

## Key custody

- Generate the key on the drill host: `attome drill keygen --out <dir>` writes `drill-signing.key`
  (owner-only on Linux; on Windows keep the folder private) and `drill-signing.pub`. It never
  overwrites a key that is there.
- Put the public half in the deployment's `ops.drill_public_keys`; the private key never leaves the
  drill host (`ops.drill_signing_key_path` there).
- The drill key signs drill evidence only. It is not the release signing key and not any key the
  deployment uses for sessions or data.
- To rotate: generate a new pair, add its public key to `ops.drill_public_keys`, switch the drill
  host to it, and remove the old public key once no report still to be uploaded was signed with it.

## Schedules

`/api/v1/ops/drill-schedules` holds each kind's cadence (weekly, monthly, quarterly) and whether it is
on. A monthly restore drill and a monthly chaos drill are proposed and start off; an administrator
turns them on, and the drill host asks `GET /api/v1/ops/drills/due` what to run.

## Before a release is tagged

The newest restore drill must be ok and at most 7 days old. Once signed restore evidence exists,
verify the newest report with `attome drill verify` and check its `finished_at` and `overall_ok`;
until then, check the newest line of `drills.jsonl` from `attome backup drill`. When it is older or
not ok, run the drill again and do not tag until a fresh, ok result is there. The release gate does
not check this yet; it is a step of the release procedure.
