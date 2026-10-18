# Email providers

Outbound email leaves through one of three providers. Each message picks
its provider by its sender identity, the From address:

- **SMTP** (the default): the relay in `email.smtp_*` with `email.tls_mode`.
- **Amazon SES**: one `POST` to the SES v2 API with the message's raw MIME,
  signed with AWS Signature Version 4.
- **SendGrid**: the v3 mail send API.

```json
"email": {
  "enabled": true,
  "smtp_host": "smtp.example.com", "smtp_port": 465,
  "smtp_user": "mailer", "smtp_password": "${SMTP_PASSWORD}",
  "smtp_from_address": "noreply@example.com", "smtp_from_name": "Example",
  "providers": {
    "default": "smtp",
    "by_sender": { "billing@example.com": "ses", "news@example.com": "sendgrid" },
    "ses": {
      "region": "eu-west-1",
      "access_key_id": "${SES_ACCESS_KEY_ID}",
      "secret_access_key": "${SES_SECRET_ACCESS_KEY}"
    },
    "sendgrid": { "api_key": "${SENDGRID_API_KEY}" }
  }
}
```

`by_sender` matches the From address in any case. Every other address
takes `default`, or SMTP when `default` is unset. If a message names a
provider whose block is missing, the send fails as a configuration error,
before any lookup or network call. `ses.endpoint` and `sendgrid.endpoint`
override the public endpoints, for example to use a VPC endpoint or the
SendGrid EU region. `ses.session_token` carries a temporary credential.

Every provider reports the same outcomes, so retries and suppression do
not depend on which one sent the message:

| Outcome | SMTP | SES and SendGrid |
|---|---|---|
| Configuration error, never retried | TLS or AUTH failure | 401, 403 or 413 |
| Transient, retried | 4xx reply, connection refused | 408, 429 or 5xx, connection refused |
| Permanent | 5xx reply | any other 4xx |
| Unknown, never retried | stall after `DATA` | the request failed after it may have been sent |

Only an SMTP rejection can suppress an address (D-661). SES and SendGrid
report bounces later, not in the answer to the send, so their rejections
never count as recipient-attributable.

`/health/dependencies` probes only an SMTP relay. If the deployment's own
sender uses another provider, the health check reports email as enabled
and not probed.
