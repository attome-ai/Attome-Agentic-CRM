# Sending through SendGrid

Attome sends to SendGrid's v3 mail send API with an API key.

## 1. Prepare SendGrid

1. **Authenticate the domain** under *Settings → Sender Authentication →
   Authenticate Your Domain*. SendGrid shows CNAME records (two DKIM keys
   and a return-path record); add them at your DNS host (see
   [the sending domain page](sending-domain.md)) and press *Verify*.
2. **Create an API key** under *Settings → API Keys* with *Restricted
   Access* and only *Mail Send* turned on. Copy it once; SendGrid does not
   show it again.

## 2. Configure

```json
"email": {
  "enabled": true,
  "smtp_from_address": "noreply@example.com",
  "smtp_from_name": "Example",
  "providers": {
    "default": "sendgrid",
    "sendgrid": { "api_key": "${SENDGRID_API_KEY}" }
  }
}
```

- To send only some senders through SendGrid, leave `default` unset and
  list them: `"by_sender": { "news@example.com": "sendgrid" }`.
- For an account in SendGrid's EU region, set
  `"endpoint": "https://api.eu.sendgrid.com"`.

Restart the server after editing.

## 3. Check it

As with SES, `/health/dependencies` does not probe SendGrid. Send yourself
a password reset and read its row in `GET /api/v1/admin/email/deliveries`.
A 401 or 403 means the key is wrong or lacks *Mail Send*; it is a
configuration error and is not retried.

## Bounces

SendGrid reports bounces later through its Event Webhook, which Attome does
not receive yet (roadmap Z8-T5). SendGrid keeps its own suppression lists
meanwhile; add an address to Attome's list by hand when it must not be
mailed (`POST /api/v1/admin/email/suppressions`).
