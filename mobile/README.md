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
