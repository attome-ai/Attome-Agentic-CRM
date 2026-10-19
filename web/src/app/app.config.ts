import { ApplicationConfig, inject, isDevMode, provideAppInitializer, provideZonelessChangeDetection } from '@angular/core';
import { provideServiceWorker } from '@angular/service-worker';
import { provideRouter, withComponentInputBinding, withPreloading } from '@angular/router';
import { provideAnimationsAsync } from '@angular/platform-browser/animations/async';
import { BrandService, IdlePreloading, provideAttomeBase } from '@attome/base';
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
    // AA12-T1: routes marked `data: { preload: true }` load when the browser is idle.
    provideRouter(routes, withComponentInputBinding(), withPreloading(IdlePreloading)),
    provideAnimationsAsync(),
    // Guards and logout return XRM users to the canonical XRM login. The
    // public website keeps its separate, root-owned sign-in modal.
    provideAttomeBase({ apiUrl: environment.apiUrl, portalKey: 'xrm', loginRoute: '/xrm/login' }),
    provideHostI18n(),
    // B13-T8: the deployment's published brand colours, for the sign-in page
    // and everything after it. Not awaited: the product's own colours show
    // until it arrives, and a failure leaves them in place.
    provideAppInitializer(() => inject(BrandService).loadPublic()),
    // B19-T1: the installable app. The service worker caches the shell and
    // hash-named render plans, fetches a new version in the background and
    // applies it on the next open (or a reload from the update notice).
    provideServiceWorker('ngsw-worker.js', {
      enabled: !isDevMode(),
      registrationStrategy: 'registerWhenStable:30000',
    }),
  ],
};
