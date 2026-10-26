# Built-in edge (one server)

One Attome server can face the internet on its own: it terminates TLS, obtains and renews its
certificate, can speak HTTP/3, and refuses abusive traffic before any authentication or database
work. This suits the Solo profile and a single-server Standard deployment. For larger profiles
(several app nodes, a load balancer, a CDN or a shared WAF) keep nginx or your own proxy in front
and leave `app.tls.enabled` off: the server then speaks plain HTTP and reads the client address
only from proxies listed in `security.trusted_proxy_cidrs`.

Every setting below is in [the configuration reference](config-reference.md); this page says how
they fit together.

## TLS from files (`app.tls`)

```json
"app": {
  "port": 443,
  "tls": {
    "enabled": true,
    "cert_path": "/etc/attome/tls/fullchain.pem",
    "key_path": "/etc/attome/tls/privkey.pem",
    "min_version": "1.2"
  }
}
```

- `cert_path` is the PEM chain, leaf first; `key_path` the PEM key (PKCS#8, PKCS#1 or SEC1). Both
  must exist at boot, or the server refuses to start and names the file.
- `min_version` is `"1.2"` (the default) or `"1.3"`.
- HTTP/2 and HTTP/1.1 are offered by ALPN on the same port.
- The files are read again every twelve hours and on `SIGHUP` (Linux), so a renewed certificate
  is picked up without a restart. A reload that fails keeps the certificate in use and logs why.

## Automatic certificates (`app.tls.acme`)

```json
"app": {
  "port": 443,
  "tls": {
    "enabled": true,
    "acme": {
      "enabled": true,
      "domains": ["crm.example.com"],
      "contact_email": "ops@example.com",
      "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
      "cache_dir": "/var/lib/attome/acme"
    }
  }
}
```

- The server orders the certificate itself over ACME and proves each domain with the
  TLS-ALPN-01 challenge on its own HTTPS port, so it must be reachable as port 443 under every name
  in `domains` (a port forward to `app.port` is fine). No certificate files are needed; `cert_path`
  and `key_path` are ignored.
- `directory_url` defaults to Let's Encrypt production. Point it at
  `https://acme-staging-v02.api.letsencrypt.org/directory` while you test, to stay clear of the
  production rate limits.
- `cache_dir` keeps the ACME account and the certificate, so a restart neither registers nor
  orders again. Keep it on persistent storage and readable only by the service account.
- Renewal runs in the background; each order, renewal and failure is logged under `tls: ACME`.
- Boot refuses `acme.enabled` without `tls.enabled`, without a domain, without a contact address
  or with a directory that is not `https://`.

## HTTP/3 (`app.tls.http3`)

HTTP/3 needs a server built with the `http3` feature (`cargo build -p attome --release --features
http3`); the standard build carries no QUIC code, and `app.tls.http3 = true` on it stops boot with
a message naming the feature.

```json
"app": { "tls": { "enabled": true, "http3": true } }
```

- The server listens on the same port over UDP as well (open UDP 443 in the firewall) and
  advertises it on every HTTPS response with `Alt-Svc: h3=":443"; ma=86400`; browsers move to
  HTTP/3 on their next request.
- Every HTTP/3 request goes through the same routes and middleware as HTTP/2. A request body
  larger than `app.max_body_size_bytes` is refused with 413.
- The QUIC endpoint keeps the certificate it started with: after a renewal, HTTP/3 uses the new
  certificate from the next restart (HTTP/1.1 and HTTP/2 use it at once).

## Certificate expiry

Every certificate, from files or ACME, logs its expiry at `info` when it is loaded and when it is
renewed (`tls: certificate expiry`, with `left_days`), and sets the gauge
`tls_certificate_expiry_seconds` to the Unix time it expires. Alert on
`tls_certificate_expiry_seconds - time() < 14 * 86400`.

## What the edge refuses before authentication

The layers run in this order on every request; each refusal counts in
`http_rejections_total{layer, reason}`, whose labels are fixed strings, never a path, address or
identifier.

| Layer | Refuses | Answer | `reason` values |
|---|---|---|---|
| `host_gate` | a staff route on a portal host, or a portal route on a staff host (`deployment.staff_hosts`, `deployment.portal_hosts`) | 404 | `host_gate`, `portal_host` |
| `waf` | a request no route can want: too many or too large headers, an over-long URI, `..` segments, NUL, a backslash, double encoding | 400 `request_rejected` | `too_many_headers`, `header_too_large`, `uri_too_long`, `dot_dot_segment`, `null_byte`, `backslash`, `double_encoded` |
| `flood` | more than `app.max_concurrent_requests` in flight on the node, or `app.max_concurrent_per_ip` from one address | 503 / 429 with `Retry-After: 1` | `global`, `per_ip` |
| `pre_auth_rate_limit` | an address over the anonymous budget, before credentials are checked | 429 | `limit`, `temporary_ban` |
| `body_limit` | a declared body over the route's limit, before the body is read | 413 | `declared_length` |
| `auth` | a missing, invalid, revoked or out-of-epoch credential, or an address outside an API key's allow list | 401 / 403 | `no_credential`, `revoked_token`, `epoch_stale`, `ip_not_allowed`, `unavailable` |
| `csrf` | a cookie-authenticated write from another site | 403 | `cross_site` |
| `rate_limit` | a caller over its category budget, an account budget or an API key's quota | 429 | `limit`, `account_budget`, `api_key_quota`, `temporary_ban` |

## Route policies in the API document

Each operation in `openapi.json` carries its policy as extensions, so tools, agents and the
server read the same thing:

| Extension | Values | Who reads it |
|---|---|---|
| `x-auth` | `session`, `api_key`, `s2s`, `public`, `portal` | The route policy table (`attome_server::route_policy`), built once at start from the merged document; absent, it is derived from the operation's security declaration. |
| `x-body-limit` | bytes | The body-limit layer, by matched route; it can only lower `app.max_body_size_bytes`. |
| `x-idempotent` | `key` (a write safe to retry with `Idempotency-Key`), `natural` (a read), or a bool | The route policy table and API clients deciding whether to retry. |
| `x-privilege` | `{entity}.read` and friends, `admin`, `authenticated`, `public` | Documentation and agents (S2-T7); authorization itself is enforced by the handlers. |
| `x-risk` | `low`, `medium`, `high` | Agents and reviewers (S2-T7). |
| `x-cache` | `etag`, `none` | Clients that revalidate with `If-None-Match`. |
| `x-rate-class` | the rate-limit category | The rate limiter's category table (Q20-T1). |

## A supervisor that hands over the socket

A supervisor can start the next version on the same listening socket instead of letting it bind,
so no connection is refused during a replacement: on Linux pass the descriptor number in
`ATTOME_LISTEN_FD`; on Windows pass the base64 of the `WSAPROTOCOL_INFOW` from
`WSADuplicateSocketW` in `ATTOME_LISTEN_PROTOCOL_INFO`, or `-` and write it as the first line of
the child's standard input. Without either variable the server binds `app.port` as usual.
