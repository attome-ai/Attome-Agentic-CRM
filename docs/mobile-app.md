# The phone app, for administrators

How to roll out Attome's Android and iOS app to your people, look after their devices, and wipe one
that is lost. Building and publishing the app itself is in [`mobile/README.md`](../mobile/README.md).

The app is a thin shell around your deployment's own web app: it holds no data of its own until a
person signs in, and it shows exactly what that person may see in a browser.

## 1. Connecting a phone to your deployment

A person opens the app and gives it your deployment's address, in one of three ways:

- **Type it**: the address people use in a browser, such as `https://crm.example.com`.
- **Scan it**: a QR code holding that address (any QR generator will make one). Scanning works on
  phones whose WebView can read barcodes; elsewhere the person types the address.
- **Have it set for them**: on a managed phone (section 4), or in a branded app locked to your
  deployment (section 5), the app opens your deployment directly and never asks.

The app accepts only `https://` addresses. It checks that `<address>/health` answers before
keeping the address, so a mistyped address fails at once. It does not need your deployment's
CORS allow-list. To point a phone at another deployment, clear the app's storage in the phone's
settings (or reinstall the app), and it asks again.

People sign in exactly as they do in a browser, with your sign-in method, MFA and password rules.

## 2. What the app does on the phone

- **Registration**: after the first sign-in the app registers the phone
  (`POST /api/v1/devices`) and keeps its device id in the phone's secure storage.
- **Unlock**: after five minutes away, the app asks for the fingerprint, face or device PIN
  again. On a managed phone, `lock_timeout_minutes` changes the five minutes.
- **Locked screen**: if the unlock is refused, the app's content stays covered until the person
  unlocks.
- **Wipe check**: when a person signs in, and every time the app is brought back, it asks the server
  whether the phone has been wiped (next section).
- **Privacy screen**: while a record whose form has any **sensitive** field is open, the app hides
  its content from the app switcher (and, on Android, from screenshots), and shows it again when the
  record is closed. Mark a field sensitive in the entity's field settings; every phone follows it.

## 3. Devices and remote wipe

These calls need the **Security** privilege. There is no screen for them yet; use the API with an
administrator's API key (`Authorization: ApiKey <public id>:<secret>`).

| To | Call |
|---|---|
| List every registered phone, with its owner, platform, last seen time and offline sync state | `GET /api/v1/admin/devices` |
| Wipe a lost or stolen phone | `POST /api/v1/admin/devices/{id}/wipe` |
| Make a phone reload all of its offline data at its next sync | `POST /api/v1/admin/devices/{id}/offline-refresh` |

A wipe takes effect in two places:

1. **At once, on the server**: in the same transaction as the security audit event, every session
   of the phone's owner is ended, on every device. The phone cannot sign back in with the tokens it
   holds.
2. **On the phone, the next time the app is opened or resumed**: the app clears every local store
   (offline records, queued changes, the saved address and the device id), reports the wipe
   (`POST /api/v1/devices/me/{id}/wiped`) and signs out. The device list then shows the wipe as
   done.

A phone that is never opened again keeps whatever offline data it already held until it is. The
server-side half is what protects your deployment: the phone's tokens no longer work. If the phone
held offline data you must account for, treat it as lost data under your own procedure.

The owner signs in again on their other devices, and on a replacement phone, which registers as a
new device.

## 4. Managed phones (Intune and other MDMs)

Deploy the app through your MDM and set its managed app configuration (Android managed
configurations, iOS `com.apple.configuration.managed`):

| Key | Value | Effect |
|---|---|---|
| `deployment_url` | your `https://` address | The app opens it directly and never shows the connect page. |
| `block_copy` | `true` | Copying or cutting the value of a sensitive field is refused. |
| `lock_timeout_minutes` | a number | Minutes away before the app asks for the fingerprint, face or PIN again (default 5). |

Microsoft Intune's app protection without enrolment (the Intune App SDK) needs a separately
wrapped build. It is not part of the standard app.

## 5. Your own branded app

A customer can publish the app under its own name, icon and colour, optionally locked to its
deployment (`deploymentUrl`), with push notifications through Attome's relay or through its own
Firebase and APNs keys (`pushMode`). The brand file and the `npm run brand` script are described in
[`mobile/README.md`](../mobile/README.md#branded-builds). The app is then published under the
customer's own Google Play and Apple developer accounts, following the release checklist there.

## Rollout checklist

1. Confirm people can sign in to the deployment in a phone's browser first.
2. Mark sensitive fields in each entity's field settings: the privacy screen and the copy block
   follow them (sections 2 and 4).
3. Choose how phones connect: an address, a QR code on your intranet, MDM configuration, or a
   branded app.
4. Pilot with a few people, then check `GET /api/v1/admin/devices` shows their phones.
5. Write down who may request a wipe and how. Practise one wipe on a test phone.
