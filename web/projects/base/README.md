# `@attome/base`

The generic Angular layer of the Attome XRM platform: session and refresh,
the API/error contract, i18n, theming, the account pages, the dialog and
step-up hosts. It knows nothing about XRM entities, endpoints or screens —
`@attome/xrm` builds on it, and the planned portal uses `@attome/sdk`
instead (D-469).

## Build order

```powershell
cd angular
npm run build:base      # writes dist/base
npm run test:base       # unit specs, from source
```

`dist/base` must exist before anything that consumes the built package is
compiled (`build:xrm`, the host app's production build, `test:xrm`).
`ng serve` is the exception: `angular/tsconfig.json` maps `@attome/xrm/*` to
source, so the dev server needs no rebuild.

## Entry points

| Entry point | Contents |
|---|---|
| `@attome/base` | session, API/error contract, i18n core (`LangService`, `provideLayerCatalog`), theming, pipes, the modal focus/stack utilities |
| `@attome/base/account` | the forgot/reset/verify pages and their stylesheet — lazy per route (NGB-5.1a, D-760) |
| `@attome/base/dialog` | `DialogService`/`ConfirmService`, the dialog types and `DialogHostComponent` (NGB-5.1b) |
| `@attome/base/step-up` | `StepUpService`, `StepUpPromptComponent`, `STEP_UP_NAVIGATE` (NGB-5.1c) |
| `@attome/base/i18n-ar` | the Arabic catalog only — a lazy chunk fetched on first use (D-603) |

A secondary entry point keeps its sources in its own directory and imports
base's shared services by package name (`@attome/base`); the primary entry
point never imports a secondary one except `i18n-ar` dynamically, so there is
no cycle. The moved symbols are **not** re-exported from the root (D-760
amends OD-3: D-071 publishes nothing, every consumer is in this workspace).
Moving the account pages out of the root took 27.7 kB out of the host's
`main` (D-311 item 1).

## Catalogs per layer

Base's catalog holds base's own namespaces only (`dialog`, `errors`, `auth`,
`forgotPassword`, `resetPassword`, `verifyEmail`, `stepUp`). A layer registers
its own with `provideLayerCatalog(en, loadAr)` where it mounts (D-761):
`@attome/xrm` through `provideXrmI18n()` (`@attome/xrm/core/i18n`, Arabic in
`@attome/xrm/core/i18n-ar`) in the xrm route tree, guarded by
`layerCatalogsReady`; the host through `provideHostI18n()` in `app.config.ts`.
A new key goes in the catalog of the layer whose screen shows it.

## Removed surface

`LoginPageComponent` (unrouted; OD-1) and `ErrorDialogService` are gone
(NGB-5.3). The page chrome its stylesheet carried moved into
`account/account-forms.css`, which the three account pages now use alone.
`ListMeta`/`ListResponse` stay: `@attome/xrm`'s entity and trd services
import `ListResponse` from this package.

## Peers

`@angular/common`, `@angular/core`, `@angular/router`, `rxjs`,
`@jsverse/transloco` and `@jsverse/transloco-messageformat` (`^8.4.0`). All
six are injected or imported unconditionally, so none is marked optional
(NGB-0.1).

## Conventions

- **Session**: never a client-side "logged in" marker (D-129). The store is
  in-memory and resolved from `GET /api/v1/auth/session`; bootstrap does not
  block first paint, the guard waits.
- **Refresh**: one `POST /auth/refresh` in flight per injector
  (`RefreshCoordinator`), only GET/HEAD and idempotency-keyed writes retried
  (NGB-2.5), foreign origins uncredentialed and never refreshed (D-144).
- **Errors**: `ApiService` rejects with a sanitised `ApiError` — never
  `HttpErrorResponse.message`, which embeds the URL. Render it through
  `LangService.errorText(err)`: `errors.<kind>` in the active language, with
  the server's own text kept only for `validation` and `rule_violation`
  (OD-8, NGB-2.3).
- **Navigation state**: only flat, validated data in `sessionStorage`. The
  library's one reader of `?returnUrl=` is `consumeReturnUrl`, which validates
  with `isSafeReturnUrl` (NGB-1.3 / OD-5); the host `LoginComponent` goes
  through it after every sign-in.
- **i18n**: catalogs are bundled TS modules. English is eager; every other
  language is a lazy entry point, and the first render waits at most
  `FIRST_RENDER_BOOT_TIMEOUT_MS` (3 s) for it before painting in English
  (D-603, amended by D-668).
- **Wire types**: prefer `ApiComponents['schemas'][…]` from the generated
  document. A hand-written type that duplicates a generated schema name is a
  spec failure (`types.lockstep.spec.ts`, NGB-2.4).
- **Layering**: no `@attome/xrm` import and no XRM endpoint knowledge. One
  documented exception: `CurrencyService` renders a stored XRM field type's
  currency, keeps its one-week `localStorage` rate cache (source
  `public/currency-rates.json`, key per `portalKey`, failure: stale table
  then built-in fallback) and is owned by D-490 rather than by this layer.

## Testing

`npm run test:base` runs Vitest through `@angular/build:unit-test` from
source, with `runnerConfig: false` (NGB-0.4): there is no project Vitest
config or setup file — `@angular/build` initialises and resets TestBed itself.
