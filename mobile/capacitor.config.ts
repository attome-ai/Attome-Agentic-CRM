import type { CapacitorConfig } from '@capacitor/cli';

// B17-T1: the shell opens the bundled connect page (www/); once a deployment's
// address checks out it navigates the WebView there. allowNavigation lets the
// WebView leave the bundle at all; connect.js decides which address it goes to
// (https only, http only for 127.0.0.1 in a debug build).
const config: CapacitorConfig = {
  appId: 'io.attome.app',
  appName: 'Attome',
  webDir: 'www',
  server: {
    androidScheme: 'https',
    allowNavigation: ['*'],
  },
  plugins: {
    // The health check runs through native HTTP, so the deployment's CORS
    // allow-list need not name the app's own origin.
    CapacitorHttp: { enabled: true },
  },
};

export default config;
