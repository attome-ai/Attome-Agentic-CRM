# Sending through Amazon SES

Attome sends to SES with one signed `POST` per message to the SES v2 API
(`/v2/email/outbound-emails`, the raw MIME message, AWS Signature Version
4). No AWS SDK or SMTP credentials are involved.

## 1. Prepare SES

In the AWS console, in the region you will send from:

1. **Verify the domain** under *Identities → Create identity → Domain*,
   with Easy DKIM. SES shows three CNAME records; add them at your DNS host
   (see [the sending domain page](sending-domain.md)) and wait until the
   identity shows *Verified*.
2. **Leave the sandbox**: a new SES account sends only to verified
   addresses. Request production access before mailing customers.
3. **Create an IAM user or role** for Attome whose policy allows
   `ses:SendEmail` and `ses:SendRawEmail` on that identity, and create an
   access key for it. On AWS hosts a role's temporary credential works too
   (`session_token` below).

## 2. Configure

```json
"email": {
  "enabled": true,
  "smtp_from_address": "noreply@example.com",
  "smtp_from_name": "Example",
  "providers": {
    "default": "ses",
    "ses": {
      "region": "eu-west-1",
      "access_key_id": "${SES_ACCESS_KEY_ID}",
      "secret_access_key": "${SES_SECRET_ACCESS_KEY}"
    }
  }
}
```

- `default: "ses"` sends everything through SES. To send only some senders
  through it, leave `default` unset (SMTP) and list them:
  `"by_sender": { "billing@example.com": "ses" }`.
- `ses.endpoint` replaces `https://email.{region}.amazonaws.com`, for a VPC
  endpoint. `ses.session_token` carries a temporary credential's token.
- A message that names `ses` while the `ses` block is missing fails as a
  configuration error before any network call.

Restart the server after editing.

## 3. Check it

`/health/dependencies` probes only SMTP relays, so with SES as the
deployment's sender it reports email as enabled and not probed. Send
yourself a password reset and read its row in
`GET /api/v1/admin/email/deliveries`:

| SES answers | Attome records |
|---|---|
| 401, 403 or 413 | a configuration error, not retried: check the key, the IAM policy, the region and the message size |
| 408, 429 or 5xx | transient, retried with backoff |
| any other 4xx | permanent |

## Bounces and complaints

SES reports bounces and complaints after the send, not in its answer, so an
SES rejection never suppresses an address on its own. Attome does not yet
receive SES's bounce and complaint notifications (roadmap Z8-T5); until it
does, keep SES's account-level suppression list on and add an address to
Attome's own list by hand when it must not be mailed
(`POST /api/v1/admin/email/suppressions`).
