# Limits

Every limit Attome enforces, from `attome_config::limits::LIMITS`. A limit is either a
**resource** limit (it bounds the memory, time or connections one piece of work uses) or an **abuse**
limit (it slows a caller who is guessing, flooding or scraping). A limit on how many statements one
request or transaction may run is not allowed: such work goes to the background path instead.

A boot-config limit is set in the configuration file and checked at start; a value outside its
range stops the server with a message naming the key, the value and the range. A runtime setting
changes without a restart. Each refusal counts in `limit_hits_total` and in the daily
`limit_usage_daily` table.

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
| `ai.spend.deployment_monthly` | what the whole deployment may spend on models in a month | resource | runtime setting | no cap |
| `ai.spend.caller_monthly` | what one person may spend on models in a month | resource | runtime setting | no cap |
| `ai.spend.agent_monthly` | what one agent may spend on models in a month | resource | runtime setting | no cap |
| `http.max_body_bytes` | the largest request body read | resource | boot config | 10 MiB |
| `bulk.max_records_per_request` | records one bulk request may carry; more go through a staged import | resource | runtime setting | 500 records |
| `auth.mfa_challenge_max_attempts` | wrong codes one second-factor challenge accepts before it is spent | abuse | boot config | 5 attempts |
