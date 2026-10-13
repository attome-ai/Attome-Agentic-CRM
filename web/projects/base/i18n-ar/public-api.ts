/*
 * @attome/base/i18n-ar — the Arabic translation catalog, as its own entry
 * point so it is not part of the initial bundle.
 *
 * It measured ~119 KB of the host app's initial download while every English
 * visitor had no use for it. `LangService` now `import()`s this entry point the
 * first time Arabic is needed (a saved preference at startup, awaited by an app
 * initializer so there is no English flash, or a switch from the UI). It stays
 * bundled JS — no HTTP/assets round trip, per P-i18n-a11y §4.1 — just a lazy
 * chunk instead of an eager one.
 *
 * This entry point must never import `@attome/base`: the primary entry point
 * imports it (dynamically), so the reverse edge would be a cycle.
 */
export { ar } from './ar.catalog';
