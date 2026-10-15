import { EnvironmentProviders, inject, isDevMode, makeEnvironmentProviders, provideAppInitializer } from '@angular/core';
import { provideHttpClient, withInterceptors } from '@angular/common/http';
import { metadataVersionInterceptor } from './metadata-version';
import {
  TRANSLOCO_MISSING_HANDLER,
  provideTransloco,
  translocoConfig,
  TRANSLOCO_TRANSPILER,
} from '@jsverse/transloco';
import { ATTOME_CONFIG, AttomeBaseConfig } from './config';
import { authInterceptor } from './auth.interceptor';
import { AuthService } from './auth.service';
import { InMemoryTranslocoLoader } from './i18n/transloco.loader';
import { WarnOnceMissingHandler } from './i18n/missing-handler';
import { LazyMessageFormatTranspiler } from './i18n/lazy-messageformat.transpiler';
import { LangService } from './lang.service';

/**
 * P-i18n-a11y §4.1 — the runtime catalog-library wiring (Transloco chosen
 * over `@angular/localize` per that plan's own rationale: this app's
 * LangService.toggle() is already a live in-session switch, which
 * `@angular/localize`'s one-bundle-per-locale model can't reproduce without
 * a page reload). Exported separately from provideAttomeBase() so
 * lang.service.spec.ts/translate.pipe.spec.ts can provide just this,
 * without pulling in HTTP/auth/session-bootstrap providers a pure i18n unit
 * test has no use for.
 */
export function provideAttomeI18n(): EnvironmentProviders {
  return makeEnvironmentProviders([
    provideTransloco({
      config: translocoConfig({
        availableLangs: ['en', 'ar'],
        defaultLang: 'en',
        fallbackLang: 'en',
        reRenderOnLangChange: true,
        prodMode: !isDevMode(),
        // NGB-3.5 / OD-10 — an ar-missing key resolves against `en` instead of
        // rendering its own raw key; parity is still enforced by
        // catalog-coverage.spec.ts. `logMissingKey` is off because
        // WarnOnceMissingHandler below is the one warning, and it fires in
        // production too (the default is dev-only).
        missingHandler: { useFallbackTranslation: true, logMissingKey: false },
      }),
      loader: InMemoryTranslocoLoader,
    }),
    { provide: TRANSLOCO_MISSING_HANDLER, useClass: WarnOnceMissingHandler },
    // ICU MessageFormat plugin (plurals/gender/select) — see
    // resetPassword.minLength in i18n/en.catalog.ts / base/i18n-ar/ar.catalog.ts for the
    // real, shipped example this plan's §3 goal requires.
    // biDiSupport: true — this catalog mixes an LTR (en) and RTL (ar)
    // locale, unlike the plugin's own LTR-only default example.
    //
    // Deliberately NOT `provideTranslocoMessageformat()`: that references the
    // plugin eagerly, which drags `@messageformat/core` (CommonJS, so no
    // tree-shaking) into the initial bundle for every visitor. The wrapper
    // below `import()`s it instead — same ICU behaviour, off the critical
    // path. See lazy-messageformat.transpiler.ts for the swap mechanics.
    {
      provide: TRANSLOCO_TRANSPILER,
      useFactory: () => new LazyMessageFormatTranspiler({ locales: ['en', 'ar'], biDiSupport: true }),
    },
    // The Arabic catalog is a lazy chunk (i18n/catalogs.ts). When the saved
    // language is Arabic, hold the first render until it has landed — a few
    // milliseconds from the same origin — so an Arabic user never sees the
    // English UI flash first. An English session resolves immediately.
    provideAppInitializer(() => inject(LangService).ready),
  ]);
}

/**
 * P-session-refresh-hardening (D-129): resolves the in-memory session from
 * `GET /api/v1/auth/session` — the app never starts from a client-side
 * "logged in" marker.
 *
 * This *starts* the bootstrap and returns immediately rather than awaiting
 * it. Returning the promise (as it originally did) made Angular hold the
 * first paint until the round trip settled, so every page load — including
 * the public landing and login pages, which need no session at all — waited
 * on the backend, and with the backend down the app showed a blank page for
 * however long the browser took to fail the connection (two refused
 * connects, several seconds on a typical dev box).
 *
 * D-129's actual invariant is unchanged: no authorization decision is made
 * from a client-side marker, and none is made before the server has
 * answered. Only the *place* the wait happens moved — from every page load
 * to `authGuard`, which awaits `sessionReady()` on the guarded routes that
 * genuinely need the answer.
 *
 * NGB-4.3 — `provideAppInitializer` (D-308's modern form) replaces the
 * deprecated multi-provider `APP_INITIALIZER` token. Same one-shot, same
 * fire-and-forget semantics: the returned initializer must not be awaited by
 * Angular, and it is not.
 */

/**
 * Call in your app's `providers` array.
 *
 * @example
 * bootstrapApplication(AppComponent, {
 *   providers: [
 *     provideAttomeBase({ apiUrl: 'http://localhost:8080' }),
 *     provideRouter(routes),
 *   ]
 * });
 */
export function provideAttomeBase(config: AttomeBaseConfig): EnvironmentProviders {
  return makeEnvironmentProviders([
    provideHttpClient(withInterceptors([authInterceptor, metadataVersionInterceptor])),
    { provide: ATTOME_CONFIG, useValue: config },
    provideAppInitializer(() => { inject(AuthService).sessionReady().subscribe(); }),
    provideAttomeI18n(),
  ]);
}
