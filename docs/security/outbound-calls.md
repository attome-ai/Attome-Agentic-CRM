# Outbound calls

Every HTTP call Attome makes on its own, such as to a model server, a payment gateway, an identity
provider, a customer's webhook or a vendor's API, goes through one guarded client
(`attome_outbound::http`). Code that builds a `reqwest` client any other way fails the
`outbound_client_guard` test.

## What the guard refuses

- **Private addresses.** Loopback, private ranges (RFC 1918, unique local), carrier-grade NAT and the
  other special-purpose blocks are refused, unless the call's purpose lists that host (see below).
  This applies to a host name when it resolves, so the address the connection actually uses is the one
  that was checked, and to an IP-literal URL on every request.
- **Cloud metadata addresses, always.** Link-local addresses (`169.254.0.0/16`, `fe80::/10`, where the
  AWS, GCP and Azure metadata services and the ECS task endpoint live), AWS's `fd00:ec2::254` and
  Alibaba's `100.100.100.200` are refused for every purpose, listed or not.
- **Redirects to either.** Each redirect hop is checked the same way. A purpose that should never follow
  a redirect, such as a token exchange, follows none.
- **Proxies from the environment.** `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are ignored, because a
  proxy would resolve the host outside the guard.

## A network that reaches the internet through a proxy

Set `deployment.outbound_proxy` (an `http://` or `https://` URL, which may carry credentials; keep it in
an environment variable, `${OUTBOUND_PROXY}`). Calls to public hosts then go through it, and hosts a
purpose lists as private (below) are still reached directly. Through the proxy the guard still refuses a
private or metadata IP literal and checks every redirect, but the proxy resolves host names, so its own
egress rules decide where a name may lead: allow only the destinations Attome needs.

A refused request fails before anything is dialed, with an error naming the refused host
(`refused-by-ssrf-guard://<host>/`), and the server logs it at `warn` with the purpose.

## Which private hosts each purpose may reach

A purpose lists a private host only when the host comes from the operator's configuration, or from one
connector's own settings, and never from a request. There is no global allow-list.

| Purpose | What it calls | Private hosts it may reach |
|---|---|---|
| Model servers (generation, embedding and the other inference clients) | the configured model server | that server's host |
| Model discovery and outside MCP servers | an AI provider's or MCP server's base URL | that host, when it is inside the deployment |
| Sign-in (OpenID Connect) | discovery, keys and token endpoints | the configured issuers' hosts (`oidc.providers`, `portal.oidc_providers`) |
| Breached-password check | the range service | the configured range URL's host |
| Email (SES, SendGrid) | the provider's API | the configured endpoint's host |
| Alert webhooks | `observability.alert_webhooks` | those webhooks' hosts |
| Bundle pull | `deployment.bundle_ref` | its host |
| Document rendering | the render sidecar | `docgen.render_service_url`'s host |
| Asterisk calls and recordings | the customer's PBX | that connector's `base_url` host |
| Fleet console (development builds) | customer servers | loopback only |
| `attome status`, `attome secrets`, `attome model` | the operator's own server | the server named on the command line |
| Twilio, SMS, push, video meetings, mailbox sync, Gmail, Microsoft Graph, Meta, Google reviews, ZATCA | the vendor's API | none |
| Webhooks, workflow webhook steps, REST connectors, the web crawler, payment gateways | an address an administrator or user supplied | none |

An on-premise system that a connector must reach on a private address is listed in that connector's own
settings, never globally.
