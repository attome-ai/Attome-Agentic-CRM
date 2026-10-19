// Public API surface of @attome/base

// P-api-contract Phase 2 — generated from the backend's OpenAPI document by
// `npm run generate:api` — re-run it after any wire-type change, because
// nothing else catches drift. Prefer these over hand-written
// interfaces for any new call site: `ApiComponents['schemas']['<Name>']` is the
// backend's actual wire shape, checked by the compiler instead of by review.
// The hand-written types below are being migrated incrementally, not in one
// pass (P-api-contract §4).
export type {
  paths as ApiPaths,
  components as ApiComponents,
  operations as ApiOperations,
} from './lib/generated/api-types';

export { ATTOME_CONFIG, AttomeBaseConfig } from './lib/config';
export { ApiService, MAX_ALL_PAGES_ITEMS } from './lib/api.service';
export type { Page } from './lib/api.service';
// Solution 7 (D-785) — the changeset header and the 409 refusal codes.
export { CHANGESET_HEADER, CHANGESET_REFUSAL_CODES, changesetRefusalCode } from './lib/api.service';
export type { ChangesetRefusalCode } from './lib/api.service';
export { AuthService }                     from './lib/auth.service';
export { authInterceptor }                 from './lib/auth.interceptor';
export { authGuard }                       from './lib/auth.guard';
export { provideAttomeBase, provideAttomeI18n } from './lib/provide';
export { ThemeService }                    from './lib/theme.service';
export { ShortcutRegistry, isTypingTarget } from './lib/shortcut-registry.service';
export { CommandRegistry }                  from './lib/command-registry.service';
export { LiveChannel }                      from './lib/live-channel.service';
export { UiTextOverrides }                  from './lib/ui-text-overrides.service';
export { MetadataVersion, METADATA_VERSION_HEADER, metadataVersionInterceptor } from './lib/metadata-version';
export type { LiveRecordChange, LiveRecords } from './lib/live-channel.service';
export type { PaletteCommand }             from './lib/command-registry.service';
export type { Shortcut }                   from './lib/shortcut-registry.service';
export { BrandService }                    from './lib/brand.service';
export type { Branding }                   from './lib/brand.service';
export { CurrencyService }                 from './lib/currency.service';
export type { CurrencyRate }               from './lib/currency.service';
export { LangService }                     from './lib/lang.service';
export { compareText, textCollator, textDirection } from './lib/text-direction';
// AA12-T1: the next screens' code loads while the browser is idle.
export { IdlePreloading, IDLE_PRELOAD_TIMEOUT_MS, preloadAllowed } from './lib/idle-preloading';
// B16-T2: GS1 element strings and GTIN check digits, for scanning.
export { FNC1, isValidGtinCheckDigit, parseGs1 } from './lib/scan/gs1';
export type { Gs1Fields } from './lib/scan/gs1';
export { TranslatePipe }                   from './lib/translate.pipe';
export { LocalDatePipe, localeTag, localDay } from './lib/local-date.pipe';
export {
  HIJRI_FIRST_YEAR, HIJRI_LAST_YEAR, HIJRI_MONTHS_AR, HIJRI_MONTHS_EN,
  formatHijri, fromHijri, hijriMonthName, toHijri,
} from './lib/hijri';
export type { HijriParts } from './lib/hijri';
export { LocalNumberPipe }                 from './lib/local-number.pipe';
export { UserPreferencesService, isValidTimeZone } from './lib/user-preferences.service';
export type { DisplayCalendar, DisplayDigits } from './lib/user-preferences.service';
export { initGoogleIdentityOnce }          from './lib/google-identity';
export type { GoogleIdentityGlobal }       from './lib/google-identity';

// NGB-5.2a / D-761 — each layer (base, xrm, the host) owns its catalog and
// registers it where it mounts; base's catalog holds base's own copy only.
export { provideLayerCatalog, layerCatalogsReady } from './lib/i18n/layer-catalog';
export type { LayerCatalog }                       from './lib/i18n/layer-catalog';
export { ATTOME_LANGUAGES, DEFAULT_LANGUAGES, fallbackChain } from './lib/i18n/languages';
export type { LanguageDef }                        from './lib/i18n/languages';

// Used by `@attome/base/dialog` and `@attome/base/step-up` (NGB-5.1b/c, D-760):
// one modal stack for the whole app, so it has to be one module instance.
export { trapFocus }                       from './lib/a11y/focus-trap';
export { pushModal }                       from './lib/a11y/modal-stack';
export type { ModalHandle }                from './lib/a11y/modal-stack';

// The account pages, the dialog and the step-up flow live in their own entry
// points — `@attome/base/account`, `/dialog`, `/step-up` (NGB-5.1, D-760) —
// and are not re-exported here: a primary→secondary re-export is a cycle.

export { isMfaChallenge } from './lib/types';
export type {
  ApiError, ApiErrorKind, DuplicateMatchRef,
  AuthResponse, GoogleAuthRequest, LoginRequest, RegisterRequest,
  OidcProviderInfo, IdentityLinkInfo,
  MfaChallenge, MfaVerifyBody, MfaPendingEnrollBody, MfaEnrollResponse,
  MfaPendingConfirmResponse, MfaStatus, MfaRecoveryCodes,
  ResetRequestBody, ResetConfirmBody, VerifyEmailConfirmBody, Ack,
  ListMeta, ListResponse,
  Session,
  StepUpStatus, StepUpChallenge, StepUpVerifyRequest, StepUpElevation,
  CreateApiKeyRequest, ApiKeyCreated,
} from './lib/types';

// NGB-1.3 / OD-5 — the one sanctioned reader of the guard/interceptor's
// `?returnUrl=`, and the validator it (and the step-up flow) uses.
export { consumeReturnUrl, isSafeReturnUrl } from './lib/return-url';
export type { ColorScheme, ColorPalette, ThemeMode } from './lib/theme.service';
export type { Lang }                                 from './lib/lang.service';
export type { Translation }                          from '@jsverse/transloco';

// B14-T1: guided tours (the overlay that shows them lives in @attome/xrm/shell).
export { TourService }                                from './lib/tours/tour.service';
export type { ActiveTour }                            from './lib/tours/tour.service';
export { TOURS_SEEN_SETTING, autoTour, localText, routeMatches, tourFor } from './lib/tours/tour';
export type { LocalText, Tour, TourPlacement, TourStep } from './lib/tours/tour';
