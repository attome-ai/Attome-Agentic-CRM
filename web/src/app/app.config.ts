import { ApplicationConfig, provideZonelessChangeDetection } from '@angular/core';
import { provideRouter, withComponentInputBinding } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { provideAttomeBase } from '@attome/base';
import { environment } from '../environments/environment';
import { routes } from './app.routes';
import { provideHostI18n } from './i18n/provide-host-i18n';

// XRM form providers live in the lazy XRM route tree to keep them out of the
// website's eager bundle.
export const appConfig: ApplicationConfig = {
  providers: [
    // Redundant on Angular v21+ — `bootstrapApplication` already prepends the
    // zoneless scheduler and nothing here overrides it — but stated explicitly
    // so the intent survives. It is also a tripwire: adding
    // `provideZoneChangeDetection()` alongside it logs NG0408 in dev instead of
    // silently dragging zone.js scheduling back in.
    provideZonelessChangeDetection(),
    // No router view transitions: while one captures, the browser pauses
    // rendering and a fast second sidebar click could be lost. Pages and list
    // rows fade in with plain CSS animations instead (styles.css), which never
    // touch input.
    provideRouter(routes, withComponentInputBinding()),
    provideAnimationsAsync(),
    // Guards and logout return XRM users to the canonical XRM login. The
    // public website keeps its separate, root-owned sign-in modal.
    provideAttomeBase({ apiUrl: environment.apiUrl, portalKey: 'xrm', loginRoute: '/xrm/login' }),
    provideHostI18n(),
  ],
};
