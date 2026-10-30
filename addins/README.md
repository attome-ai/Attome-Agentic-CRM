# Mail add-ins

The Outlook add-in and the Gmail add-on (C7-T1) show, for the open email, the sender's contact in
Attome with their account's open opportunities and cases, and let the person log the email on the
contact, create a lead for an unknown sender or a case from the email, and use a suggested reply
template. Both sign in with the deployment's device grant (`docs/device-sign-in.md`): the person
approves the code in a browser where they are signed in to Attome, so every sign-in rule applies and
the add-ins act with exactly the person's own access.

| Folder | What it is |
|---|---|
| `shared/attome-mail-client.js` | The logic both share: request builders and answer readers, no I/O, English and Arabic text |
| `outlook/` | An Office.js task pane for Outlook (read and compose), the `attome-outlook` client |
| `gmail/` | An Apps Script Gmail add-on (CardService), the `attome-gmail` client |

## Tests

```
cd addins/outlook && npm test
cd addins/gmail && npm test
```

Node's own test runner; nothing to install.

## Outlook

```
cd addins/outlook
node build.mjs --url https://crm.example.com
```

writes `dist/`: serve its files at `https://crm.example.com/addins/outlook/` (the same origin as the
API, so no CORS entry is needed; from another origin, add it to `cors.allowed_origins`) and upload
`dist/manifest.xml` in the Microsoft 365 admin center (Integrated apps), or sideload it in Outlook.
The task pane loads `office.js` from `appsforoffice.microsoft.com`, so a content security policy on
those files must allow that script. The session is kept in the add-in's own browser storage and
sent as `Authorization: Bearer`.

## Gmail

```
cd addins/gmail
node build.mjs --url https://crm.example.com
```

writes `dist/` (`appsscript.json` allowing only that deployment, `AttomeMail.js`, `Code.js`). Push
it to an Apps Script project with `clasp push` and deploy it from the Google Workspace admin console,
or test it from the Apps Script editor (Deploy, Test deployments). The deployment address and the
session are kept in the person's own user properties. Gmail cannot poll in the background, so after
approving the code the person presses "Signed in." to finish.
