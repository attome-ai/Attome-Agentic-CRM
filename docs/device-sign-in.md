# Device sign-in

A device that cannot show the sign-in page itself (the `attome` CLI, the Outlook add-in, the Gmail
add-on) signs a person in through the OAuth 2.0 device authorization grant (RFC 8628, V2-D1415).
The person approves it from a browser where they are already signed in, so every sign-in rule,
MFA requirement and identity provider of a browser sign-in has already applied.

## The flow

1. The device asks:

   ```
   POST /api/v1/oauth/device_authorization
   Content-Type: application/x-www-form-urlencoded

   client_id=attome-cli
   ```

   and receives `device_code` (kept on the device), `user_code` (`XXXX-XXXX`, shown to the person),
   `verification_uri` (`<public_frontend_url>/xrm/device`), `verification_uri_complete`,
   `expires_in` (600) and `interval` (5).
2. The person opens the page signed in, enters the code (or follows the complete link), sees which
   application asks and approves or denies it. The page calls `GET /api/v1/oauth/device?user_code=`
   and `POST /api/v1/oauth/device/approve`. Only a browser session may approve: an API key or
   another device's session gets 403.
3. The device polls every `interval` seconds:

   ```
   POST /api/v1/oauth/device/token
   grant_type=urn:ietf:params:oauth:grant-type:device_code&client_id=attome-cli&device_code=...
   ```

   It gets `authorization_pending` until the person decides, `slow_down` when it polls too fast
   (the interval then grows by five seconds), `access_denied` or `expired_token` at the end, and
   once approved `{ access_token, token_type: "Bearer", expires_in, refresh_token }`. A grant works
   once.

The access token goes in `Authorization: Bearer <access_token>`. When it expires, the device
redeems the refresh token at the same endpoint (`grant_type=refresh_token&client_id=...&
refresh_token=...`) for the next pair; each refresh token works once, and presenting a spent one
again ends the session, as for a browser.

## The CLI

```
attome login --target prod --url https://crm.example.com
attome targets
attome model export --out meta --target prod
attome logout --target prod
```

`attome login` runs the flow above as `attome-cli`: it prints the code and the page, polls, and
keeps the session under `attome:<target>` in Windows Credential Manager on Windows, and elsewhere in
a file only the user can read (`credentials/<target>.json` in the config directory). The target's
URL goes in `targets.json` in the user's config directory (`%APPDATA%ttome`,
`~/Library/Application Support/attome`, or `$XDG_CONFIG_HOME/attome`; `ATTOME_CONFIG_DIR` overrides
it), and the first target signed in becomes the default. A command given `--target` uses that
session and refreshes it when the access token is about to expire; a session that has ended is
forgotten and the command asks to sign in again.

## What the session is

An ordinary session of the person: their roles and record access, their role's sign-in rules and
session limit, listed among their sessions (and ended from there), and audited as a sign-in
(`login device:<client>`). Its authentication time is the approving browser session's, so it is
never fresher than that sign-in, and its method (`amr`) is `dev`, never a factor: a device session
cannot step up or approve another device. The approval itself is audited (`Credential` + `Create`,
`device sign-in approved: <application>`).

The clients that may ask are `attome-cli`, `attome-outlook` and `attome-gmail`. They are public
clients: they hold no secret, which is why approval needs the person.

The device token endpoint is not `/api/v1/oauth/token`: that one is the S2S endpoint for machine
clients, which act as a service user, never as a person.
