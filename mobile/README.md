# Attome on phones

A Capacitor 7 shell (B17): it opens a connect page bundled in `www/`, checks the address a person
types or scans (`GET <address>/health` must answer 200), keeps it, and moves the WebView to that
deployment's web app. Opening the app again goes straight there; `index.html?change` asks again.

- Only `https://` addresses are accepted; `http://127.0.0.1` too in a debug build, for a server on the
  same machine.
- The health check runs through Capacitor's native HTTP (`CapacitorHttp`), so the deployment's CORS
  allow-list does not need the app's origin.
- The page follows the phone's language: Arabic right to left, English otherwise.
- Scanning uses the WebView's `BarcodeDetector` where the phone has it; elsewhere the person types
  the address.

## The native projects

`android/` and `ios/` are generated, once, on the build machine and then committed:

```powershell
cd mobile
npm ci
npx cap add android
npx cap add ios        # on macOS only
npx cap sync
npx cap doctor
```

## Building

**Android (Windows, Linux or macOS):** install Android Studio (with the Android SDK and a JDK 21),
then `npx cap sync android` and `npx cap open android`, or from `mobile/android`
`./gradlew assembleDebug` (`gradlew.bat assembleDebug` on Windows). The debug APK is under
`android/app/build/outputs/apk/debug/`.

**iOS:** needs macOS with Xcode 16 and CocoaPods: `npx cap sync ios`, `npx cap open ios`, then build
and sign in Xcode.

Capacitor and its plugins are pinned to exact versions in `package.json`; upgrade them together.

## Branded builds

A customer can have its own app: its id, name, icon and colour, and optionally locked to its own
deployment. Describe the brand in `brands/<brand>.json` (see `brands/example.json`):

| Field | Meaning |
|---|---|
| `appId` | The store id, such as `io.attome.acme`. |
| `appName`, `appNameAr` | The app's name in English and Arabic. |
| `iconPng`, `splashPng` | Square PNGs (1024 px icon, 2732 px splash), relative to the brand file. |
| `primaryColor` | `#rrggbb`, behind the icon and the splash. |
| `deploymentUrl` | Optional `https://` address: the app opens it directly and never shows the connect page. |
| `pushMode` | `relay` (Attome's push relay) or `own_keys` (the customer's own Firebase and APNs keys). |

Then `npm run brand -- <brand>` writes `build/<brand>/`: the shell with the brand's id and name, the
icons and splash in every Android size (through `@capacitor/assets`) and the Arabic app name. Build it
as above from that folder. Publishing under the customer's own Google or Apple developer account is a
business step agreed with the customer, outside this script.

## Managed devices

On a phone managed by Intune or another MDM, the app reads its managed configuration (Android
restrictions, iOS `com.apple.configuration.managed`) through a managed-configuration plugin registered as
`ManagedConfigurations` in the shell: `deployment_url` (an `https://` address; the app opens it and skips
the connect page), `block_copy` (`true` turns off copying sensitive fields) and `lock_timeout_minutes`.
The web app reads them through `ManagedConfigService` in `@attome/base/native`. Wrapping with Microsoft's
Intune App SDK (app protection without enrolment) is a separate build, not part of this shell.

Administrators: rolling the app out, devices and remote wipe are in
[`docs/mobile-app.md`](../docs/mobile-app.md).

## Release checklist

**Every release**

1. Bump `version` in `package.json`, and `versionName`/`versionCode` in
   `android/app/build.gradle` and the version and build in Xcode (each store refuses a build number
   it has seen).
2. `npm ci && npx cap sync`, then `npx cap doctor`.
3. Try the build on a real phone of each platform: connect by address and by QR, sign in, unlock
   after the lock timeout, and a wipe requested from `POST /api/v1/admin/devices/{id}/wipe`
   (the app clears itself and signs out on its next resume).
4. Check Arabic: switch the phone to Arabic and open the connect page and a record.

**Android (Windows, Linux or macOS)**

1. Sign with the upload key, kept outside the repository (Android Studio's *Generate Signed
   Bundle*, or `./gradlew bundleRelease` with the signing config read from environment variables).
2. Upload the `.aab` to Google Play Console: internal testing first, then production.
3. Fill in the Data safety form: the app sends what the person enters to the customer's own
   deployment; it collects nothing for Attome.

**iOS (macOS with Xcode only)**

1. In Xcode, select the team and the distribution certificate, then *Product → Archive* and
   *Distribute App* to App Store Connect.
2. Test through TestFlight before submitting for review.
3. Review notes: the app is a client for a business's own Attome server, so give the reviewer a
   demo deployment address and a demo sign-in, or the review is refused for an unusable login. Fill
   in the privacy nutrition labels the same way as Android's Data safety form.
4. Explain each permission the app asks for (camera for scanning and photos, microphone for voice
   notes, location for check-in, Face ID for unlocking) in `Info.plist`; the review refuses a
   missing or vague purpose string.

**A branded build** follows the same steps from `build/<brand>/`, under the customer's own store
accounts.

