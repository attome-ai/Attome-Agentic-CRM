# Changelog

Every release lists what changed for administrators, users and developers. A breaking change to
`/api/v1` (a removed or renamed route, a removed response status or field, a newly required request
field, a changed type) is named under `### Breaking` in the `[Unreleased]` section in the same change
that makes it; the release gate's contract step refuses a release that breaks the API silently.

## [Unreleased]

### Added
- `article.draft` never drafts twice: an article already drafted from the same record is returned,
  and one with the same title (Arabic letter forms normalised) is reported unless `force` is set.
- `GET /api/v1/admin/ai/status` and the AI status screen (`/ai/status`): the model in use and its card,
  what is switched off, how turns ended over the last day, and the switch timeline.
- `POST /api/v1/admin/ai/eval-suites/{suite}/cases/from-message`: an answer that went wrong becomes
  a case in the suite's draft, its input taken from the question it answered.
- `POST /api/v1/admin/ai/preview/summary`: exactly what a model would receive for a record summary,
  built by the same code, without generating.
- A Translate button under notes and replies translates them into the viewer's language.
- `text.translate` with a deployment glossary (`inference.translation.glossary`) and a 30-day cache
  keyed by the text, languages, glossary and model.
- `record.transitions` and `record.transition`: agents move a record through its state model on the
  ordinary update path, approvals included.
- `agent.delegate`: a supervisor agent hands a subtask to a specialist through the specialist's
  typed `handoff` contract; the specialist runs read-only in a child session (migration 0016,
  `agent_session.parent_session_ref`).
- Agent bulk actions: `record.bulk.preview`, `record.bulk.update`, `record.bulk.delete` and
  `record.bulk.status`, over the bulk engine (`attome_records::bulk::submit_bulk`, `bulk_status`).
- `GET /api/v1/admin/ai/spend` and the AI spend screen (`/ai/spend`): this month's spend per
  deployment, feature and agent against each cap, with the month forecast.
- Money budgets for AI (`inference.spend`): prices per model and monthly caps per deployment, person,
  agent and feature; near a cap generations are shortened, at a cap refused (429) before any spend.
- `record.summarize` sees the related records and the recent timeline (within a budget, every part
  filtered by the caller's grants) and reuses a summary of identical facts from a 24-hour cache.
- `query.plan`: a question becomes a query model checked against the metadata (fields, operators,
  value types, sensitive-field grants) before `query.execute` runs it.
- The `library-core` pack: party, person (four-part Arabic name, national id, iqama, Emirates ID),
  organisation, Saudi national address, work item and agreement.
- Attome v2: one `attome` binary (`attome init`, `attome serve` and the operator commands) on
  PostgreSQL alone for a single server; Redis is optional.
- The release gate (`attome-release --check`, also `attome release --check`) writes a per-OS report
  to `target/release-gate/` and checks the API contract against the previous release.
- The metadata model: forms and other metadata kinds are stored as versioned drafts, edited with
  `add`/`remove`/`move`/`set` commands (the same for people and agents), validated in three steps
  and cooked into content-hashed artefacts; administrators reach it under `/api/v1/admin/model`.
- Metadata as files: `GET /api/v1/admin/model/export` and `POST /api/v1/admin/model/import`, with
  `attome model export --out <dir>` and `attome model import --dir <dir>`, move objects as one
  readable JSON file each; import saves drafts and never publishes.
- Agents as metadata: the `agent` kind (role, instructions, tools, identity, limits, triggers,
  channels) with an agent designer at `/model/agents`, a metadata explorer at `/model/explorer`,
  and `model.<kind>.edit|describe|list` agent tools generated from the kind registry.
- One-command install: `scripts/install.sh` (Linux, installing PostgreSQL 18 with pgvector when no
  database is given) and `scripts/install.ps1` (Windows), release archives with the web app, which
  `attome serve` now serves itself, and `attome init --admin <email> --service`.
- Form render plans carry a content ETag; the web app loads each plan once per version.
- Agent daily limits: an agent's `limits.daily` caps record changes, deletes, messages and outside
  calls per day across all its sessions; a session started with `agent` (a published agent object)
  is held to them and to the agent's tools, and `GET /api/v1/admin/ai/agents/{agent}/usage` reports
  today's use.
- MCP: `tools/list` returns a core set plus `tools.search`; `initialize` carries a playbook.
- The live channel `GET /api/v1/live` tells the web app when published metadata changes.
- Install and operations: `attome service install`, `attome bundle offline`, `attome sovereignty
  report`, a sizing check in `attome init`, and the `deployment.sovereign` preset.
- Testing and release tooling: `attome test` (tiers, a Docker test stack, flaky-test reruns,
  quarantine, coverage, the coverage map), the SLO catalogue with `attome slo generate`, and gate
  steps for waivers, `cargo deny`, npm licences, SBOMs, dependency intake, install time and a boot
  smoke test.

### Breaking
- v2 renames every table, entity and API path segment that carried v1's `xrm_` or `core_` prefix
  (`/api/v1/xrm_service_ticket` is `/api/v1/service_ticket`); see `docs/roadmap-paths.md`.
- Licences are gone: `/api/v1/admin/system-health` reports `modules` instead of `license`.
