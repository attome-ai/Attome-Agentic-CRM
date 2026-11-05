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
| Restore | `attome drill restore` writes signed restore evidence, and is not in this build yet (roadmap AB4-T4). `attome backup drill` restores the newest backup into a throwaway database and records an unsigned result in the backup folder's `drills.jsonl` (see [backup](backup.md)) |
| Failover | `attome drill failover --scenario <leader\|router\|redis> --confirm <scenario> --key <file> --out <dir> ...` |
| Chaos | `attome drill chaos run --fault <name> ...` for one fault, `attome drill chaos suite --key <file> --out <dir> ...` for every fault in turn, one report each |
| Readiness | `attome drill readiness` (the preflight checks, the signing key is readable, room for a restore) |

A chaos run refuses a production deployment unless it is an approved game day
(`ops.chaos.production_game_days`, a second person's approval of `POST /api/v1/ops/chaos/requests`);
the suite never runs against production.

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
