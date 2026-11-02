# Microsoft Teams

Attome's Teams app sends notifications and approval requests to people in Teams, and shows a card
for an Attome record link pasted into a chat. It is a bot registered in your own Azure tenant: Attome
holds the bot's app id and client secret, and Teams posts what people do to your deployment.

## 1. Register the bot in Azure

1. In the Azure portal, create an **Azure Bot** (single tenant is enough). Note its **Microsoft App
   ID** and create a **client secret** for it.
2. Under **Channels**, add **Microsoft Teams**.
3. Under **Configuration**, set the **messaging endpoint** after step 2 below, to
   `https://<your deployment>/api/v1/integrations/<system id>/webhook`.

## 2. Add the bot to Attome

Create an integration system for it (Settings → Integrations, or `POST /api/v1/admin/integrations/systems`):

| Field | Value |
|---|---|
| `kind` | `rest` |
| `auth_type` | `botframework` |
| credential | `<app id>:<client secret>` |

Grant the system's service principal `integration_event.create`, as for any inbound integration.
The system's id goes in the messaging endpoint above.

What Attome accepts on that endpoint: each request carries a token Microsoft signed. Attome checks it
against Bot Framework's published keys (only keys endorsed for the Teams channel), that it was issued
by `https://api.botframework.com` for your bot's app id, that it has not expired, and that it was issued
for the same Teams service address the activity names. Anything else is refused with 401. Each
activity is taken once (Teams retries with the same id), and lands as an `integration_event` for
flows to act on. If Microsoft's keys cannot be read, Attome answers 503 rather than trusting a token
it cannot check.

## 3. Build and upload the Teams app

```
cd addins/teams
node build.mjs --url https://crm.example.com --bot-app-id <app id> --company "Example Co"
```

writes `dist/manifest.json`, `dist/ar.json` (Arabic) and the two icons. Keep the Teams app id it
prints and pass it as `--teams-app-id` for later versions, or Teams treats them as another app. Zip
the four files (at the zip's top level, no folder) and upload the zip in the Teams admin center
(**Teams apps → Manage apps → Upload new app**), then allow it for the people who should have it.

The manifest's link handler covers your deployment's host, so a pasted Attome record link shows the
record's card to people who may read it.

## Tests

```
cd addins/teams && npm test
cargo test -p attome-integration --lib botframework
```
