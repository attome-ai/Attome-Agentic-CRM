# Limits

Every limit Attome enforces, from `attome_config::limits::LIMITS`. A limit is either a
**resource** limit (it bounds the memory, time or connections one piece of work uses) or an **abuse**
limit (it slows a caller who is guessing, flooding or scraping). A limit on how many statements one
request or transaction may run is not allowed: such work goes to the background path instead.

A boot-config limit is set in the configuration file and checked at start; a value outside its
range stops the server with a message naming the key, the value and the range. A runtime setting
changes without a restart. Each refusal counts in `limit_hits_total` and in the daily
`limit_usage_daily` table.

**Warnings (AA9-T7).** `limit_usage_daily` also keeps each limit's peak use: the size a refused
request asked for, and for a rate class the requests a signed-in caller had made in the current
minute once past half the budget. A limit warns when someone was refused by it in the last seven
days or its peak reached the runtime setting `limits.warn_at_percent` (default 80, from 50 to 99)
of its value. `GET /api/v1/admin/limits` shows the warning, and once a day every administrator
gets one notification per warning limit.

| Key | Purpose | Kind | Set in | Default |
|---|---|---|---|---|
| `rate_limit.authenticated` | requests one signed-in caller may make outside a named category | abuse | boot config | 600 requests per minute |
| `rate_limit.anonymous` | requests one address may make before signing in | abuse | boot config | 60 requests per minute |
| `rate_limit.credential` | sign-in and credential attempts | abuse | boot config | 30 requests per minute |
| `rate_limit.mfa` | second-factor attempts | abuse | boot config | 20 requests per minute |
| `rate_limit.password_reset` | password reset requests | abuse | boot config | 5 requests per minute |
| `rate_limit.api` | generic API calls | abuse | boot config | 600 requests per minute |
| `rate_limit.export` | exports started | abuse | boot config | 30 requests per minute |
| `rate_limit.expensive_query` | costly queries and searches | abuse | boot config | 600 requests per minute |
| `rate_limit.presign` | file download and upload links | abuse | boot config | 20 requests per minute |
| `rate_limit.consent_capture` | portal consent captures | abuse | boot config | 600 requests per minute |
| `rate_limit.portal_status` | portal status checks | abuse | boot config | 600 requests per minute |
| `rate_limit.webchat` | web chat messages | abuse | boot config | 600 requests per minute |
| `query.timeout_ms.interactive` | how long an ordinary request's statement may run | resource | runtime setting | 5,000 milliseconds |
| `query.timeout_ms.report` | how long a report's statement may run | resource | runtime setting | 60,000 milliseconds |
| `query.timeout_ms.export` | how long an export's statement may run | resource | runtime setting | 60,000 milliseconds |
| `workflow.max_steps_per_run` | node executions one flow run may make, retries included | resource | runtime setting | 1,000 node runs |
| `workflow.max_loop_items` | items one for-each step may go through | resource | runtime setting | 10,000 items |
| `workflow.max_nesting` | sub-flows and for-each runs one run may nest inside each other | resource | runtime setting | 20 levels |
| `workflow.max_run_minutes` | minutes a flow run may last, waits included | resource | runtime setting | 43,200 minutes (30 days) |
| `ai.spend.deployment_monthly` | what the whole deployment may spend on models in a month | resource | runtime setting | no cap |
| `ai.spend.caller_monthly` | what one person may spend on models in a month | resource | runtime setting | no cap |
| `ai.spend.agent_monthly` | what one agent may spend on models in a month | resource | runtime setting | no cap |
| `http.max_body_bytes` | the largest request body read | resource | boot config | 10 MiB |
| `bulk.max_records_per_request` | records one bulk request may carry; more go through a staged import | resource | runtime setting | 500 records |
| `auth.mfa_challenge_max_attempts` | wrong codes one second-factor challenge accepts before it is spent | abuse | boot config | 5 attempts |

## Service limits per profile (Y5-T3)

`attome service install --profile <profile>` caps the service so one deployment cannot starve the
others on a shared host. On Linux the systemd unit sets `MemoryHigh` (90% of the ceiling, where the
kernel starts reclaiming), `MemoryMax` and `CPUQuota`; on Windows the service puts itself in a Job
Object with a process memory limit (Windows has no matching CPU quota). The default is `solo`;
`--profile none` sets no limit.

| Profile | Reference machine | Memory ceiling | CPU |
|---|---|---|---|
| `solo` | 4 vCPU, 16 GB | 3 GiB | 3 cores (300%) |
| `team` | 8 vCPU, 32 GB | 8 GiB | 6 cores |
| `ha` | 16 vCPU, 64 GB | 16 GiB | 12 cores |
| `scale` | 32 vCPU, 128 GB | 32 GiB | 24 cores |

The rest of each machine is left for PostgreSQL and the operating system. These are proposals sized
from `loadtest/profiles.json` until the AA2 runs measure them. v2 ships no container deployment
(V2-D470), so there are no container limits to generate; the database pool stays as `config.json`
sets it.
