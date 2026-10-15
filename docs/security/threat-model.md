# Threat model

This is the STRIDE model for the surfaces Attome v2 exposes: what can go wrong on each, and what in the
code stops it. It is reviewed when a surface is added or its trust boundary moves, and before every
release. Report a gap the way [SECURITY.md](../../SECURITY.md) describes.

STRIDE: **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of
service, **E**levation of privilege.

## Trust boundaries

- **The browser and API clients** talk to one server process (or several identical ones behind a load
  balancer) over HTTPS.
- **The server** owns one deployment's database. Each customer runs a separate deployment with its own
  database; no customer data is shared between deployments.
- **AI agents** act through the same action registry as people, under a user's identity, inside an
  agent session with its own limits.
- **Outside systems** reach the server through signed service-to-service calls, webhooks and
  connectors.
- **Portal visitors** are outside people with their own session type, never staff sessions.

## Web app and REST API (`/api/v1`)

| | Threat | Mitigation |
|---|---|---|
| S | Stolen or forged session | Signed session tokens with issuer, audience and `typ` checks; refresh rotation; per-account epoch revokes every live token on disable or password reset; MFA and step-up for sensitive actions. |
| S | Cross-site request forgery | Cookie-authenticated writes need the browser's same-origin signal (`Sec-Fetch-Site`) or are refused; CORS is an explicit allow-list. |
| T | Lost update | Every record write needs `If-Match` with the row version; a stale version is `409 version_conflict`. |
| T | Repeated or replayed write | `Idempotency-Key` replays the stored outcome, refuses a different body under the same key, and the durable tier is mandatory for bulk and import operations. |
| R | "I never changed that" | Every mutating route declares its audit event; security, access, configuration and AI changes are written in the same transaction as the change; the audit log is hash-chained and can be verified offline. |
| I | Reading records or fields without the right | Record-level access predicates on every read, list, lookup name and search; field security masks sensitive fields; a record the caller cannot read answers 404, not 403. |
| I | Error messages leaking internals | Database and internal errors are masked; responses carry a request id instead. |
| D | Request floods and huge bodies | Body-size limit and pre-authentication rate limit run before authentication; per-user and per-key rate limits after it; query cost ceiling and time limits per statement class. |
| E | Privilege escalation through the API | Privileges are resolved on the server from roles, never from the client; admin routes need `system.admin`; unlicensed or switched-off modules answer as if they did not exist. |

## Query execution (the SQL gateway: `/api/v1/query/execute`)

| | Threat | Mitigation |
|---|---|---|
| T / E | SQL injection through filters or sort | Filter values and seeks are always bound parameters with a cast from the column's metadata type; sort and filter fields must be in the query's column list; identifiers are quoted through one helper. |
| I | Reading other tables through a stored query | Stored queries run on a read-only database role and are checked at publish for the relations they touch; record-level predicates are added at run time. |
| D | Expensive queries | Plan cost ceiling (reports get a larger, still finite one), statement timeouts, offset paging capped in favour of keyset cursors. |

## AI agents and MCP

| | Threat | Mitigation |
|---|---|---|
| S | An agent acting as someone else | An agent session runs under one user's identity with its own token type (`agent_session`) that staff validation refuses. |
| T | Prompt injection steering an agent into a write | Every action goes through one gate: the closed action registry, the caller's privileges, the module switch, per-session and per-agent limits, and confirmation or four-eyes approval for risky writes; untrusted text is sanitised before it reaches the model; MCP agents only see the entities admitted for them. |
| R | Unattributed agent changes | Every agent action records the session, the agent and the user it acts for; AI configuration changes are security events. |
| I | Data leaving through the model | Personal data can be masked before a prompt; model output is filtered before it is shown; outside model providers are refused at boot unless configured on purpose. |
| D | Runaway agent loops and spend | Invocation budgets per session, daily caps per class of action, money budgets per feature, and turns refused up front while the model is down. |
| E | Tools the user could not use themselves | An action is checked against the acting user's privileges, never the agent's; the registry is closed, so a model cannot name a tool into existence. |

## Extensions and packs

| | Threat | Mitigation |
|---|---|---|
| T | A pack changing metadata it does not own | Changesets carry their layer and owner and are checksummed; platform changesets reassemble to their bundles; applying one is audited. |
| E | Executable code smuggled in configuration | Configuration and packs are data (metadata, rules, templates); business logic in a pack goes through the same engines and gates. |

## Customer portal

| | Threat | Mitigation |
|---|---|---|
| S | A portal visitor using a staff route | Portal sessions have their own token type and audience; staff validation refuses them, and portal validation refuses staff tokens. |
| I | Seeing another customer's records | Portal grants are conditions evaluated on the server for every read; sensitive fields are not exposed unless a grant allows it. |
| D | Sign-up and login abuse | CAPTCHA and per-address throttling on sign-up, login and recovery. |

## Service-to-service and integrations

| | Threat | Mitigation |
|---|---|---|
| S / T | Forged or replayed calls | HMAC-signed requests with timestamps and single-use nonces (refused if the coordination store is down: fails closed). |
| I | Server-side request forgery through connectors or webhooks | Outbound calls go through one guarded client that refuses private and link-local addresses unless allowed by configuration. |
| I | Secrets leaking | Secrets are a type with no display or serialisation; encrypted at rest with a key ring; never logged or returned. |

## Files

| | Threat | Mitigation |
|---|---|---|
| T | Malware uploads | Uploads are scanned by clamd before they are accepted; with scanning configured and clamd down, uploads wait. |
| I | Reading files without the record right | Downloads are checked against the record that owns the file, through short-lived presigned links. |

## Operations

| | Threat | Mitigation |
|---|---|---|
| D | A dependency outage taking the node down | Capability probes degrade only the features that need the dependency; readiness reflects the node's own ability to serve; read-only mode protects data when the disk fills. |
| R | Unexplained restarts | Every start and drain is recorded with version, node and who started it. |

## Out of scope

Physical security of the host, the operating system and database server hardening, and the customer's
own network controls. The deployment guide lists the settings the platform expects from them.
