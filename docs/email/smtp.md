# Sending through SMTP

SMTP is the default provider: every message whose sender has no other
provider goes to the relay named here. Use it with your own mail server or
any service that offers SMTP submission (Microsoft 365, Google Workspace,
Amazon SES's SMTP interface, a local relay).

## 1. Get the relay's details

From the mail service, note the host, the port, the security it expects and
an account allowed to send as your From address:

| The service says | `email.tls_mode` | Usual port |
|---|---|---|
| SSL/TLS, SMTPS | `"implicit"` (the default) | 465 |
| STARTTLS | `"starttls"` | 587 |
| No encryption (a relay on the same host only) | `"none"`, refused outside `APP_ENV=debug` | 25 |

## 2. Configure

In `config.json`, with the password in `.env` (never in the file):

```json
"email": {
  "enabled": true,
  "smtp_host": "smtp.example.com",
  "smtp_port": 587,
  "tls_mode": "starttls",
  "smtp_user": "mailer@example.com",
  "smtp_password": "${SMTP_PASSWORD}",
  "smtp_from_address": "noreply@example.com",
  "smtp_from_name": "Example"
}
```

`email.enabled` must be `true`; while it is `false`, password resets and
email verification answer `503 feature_unavailable` rather than trying a
relay that was never meant to be live. Restart the server after editing.

## 3. Check it

- `GET /health/dependencies` probes the relay and reports email as up or
  down with the reason.
- Send yourself a password reset, then look it up in the delivery log,
  `GET /api/v1/admin/email/deliveries`, which shows each message's status
  and its last error. `POST /api/v1/admin/email/deliveries/{id}/resend`
  sends one again.
- A TLS or AUTH failure is a configuration error and is not retried; fix the
  setting and resend.

## 4. Verify the sending domain

Receivers trust mail only from a domain that publishes SPF, DKIM and DMARC
for it. Follow [the sending domain page](sending-domain.md); for SMTP the
SPF and DKIM values come from the mail service that runs the relay.

## Bounces

An SMTP relay rejects a bad address in its answer, and that rejection is
what suppresses the address (D-661): the next message to it is not sent.
The list is at `GET /api/v1/admin/email/suppressions`; delete an entry to
let the address receive mail again.
