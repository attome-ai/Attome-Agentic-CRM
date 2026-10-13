import { computed, inject, Injectable, PLATFORM_ID, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { DOCUMENT } from '@angular/common';
import { TranslocoService } from '@jsverse/transloco';
import { ATTOME_CONFIG } from './config';
import { CATALOG_LOAD, EAGER_CATALOGS } from './i18n/catalogs';
import { LayerCatalog, LayerCatalogRegistry } from './i18n/layer-registry';
import type { ApiError } from './types';

export type Lang = 'en' | 'ar';

// Bare 'ar' resolves to Western digits under current CLDR/ICU data (Node 24's
// ICU 78.3 and modern browsers both do this) — only a region-qualified locale
// forces the 'arab' numbering system. Intl.NumberFormat/DateTimeFormat callers
// must use this, never the bare Lang code directly.
const INTL_LOCALE: Record<Lang, string> = { en: 'en-US', ar: 'ar-SA' };

/**
 * NGB-1.9 / D-668 — how long the first render waits on the saved language's
 * lazy chunk before falling back to English. Amends D-603's rule 2 ("hold the
 * first render until the Arabic catalog has landed") for the stalled-chunk
 * case: a bounded English first paint beats an unbounded blank page.
 */
export const FIRST_RENDER_BOOT_TIMEOUT_MS = 3_000;

/**
 * Resolves when `load` settles **or** after `timeoutMs`, whichever comes
 * first. Never rejects: the caller here is an app initializer, and a slow
 * catalog must not fail startup. The load itself keeps running — this only
 * bounds the wait.
 */
export function raceBootDeadline(
  load: Promise<unknown>,
  timeoutMs: number = FIRST_RENDER_BOOT_TIMEOUT_MS,
): Promise<void> {
  return new Promise<void>(resolve => {
    const timer = setTimeout(resolve, timeoutMs);
    const settle = () => { clearTimeout(timer); resolve(); };
    void load.then(settle, settle);
  });
}

/**
 * P-i18n-a11y §4.1 — thin facade over TranslocoService. `current` stays this
 * service's own signal (not derived from Transloco's langChanges$);
 * TranslocoService.setActiveLang() is called alongside it purely to keep the
 * catalog's active language in sync for translate()/TranslatePipe.
 *
 * Catalog loading. English is registered synchronously in the constructor, so
 * an English session never waits on anything. The Arabic catalog is its own
 * lazy chunk (`@attome/base/i18n-ar`, see i18n/catalogs.ts), fetched the first
 * time Arabic is needed:
 *
 * - at startup, when the saved preference is Arabic — `ready` covers that load,
 *   and `provideAttomeI18n()` registers an app initializer that awaits it, so
 *   the first render is already Arabic (no English flash);
 * - on `set('ar')`/`toggle()` from the UI — the switch applies once the chunk
 *   has landed, so the page never shows RTL layout over untranslated keys.
 *
 * Once a catalog is registered, `set()` applies synchronously (the returned
 * promise is already settled), exactly as before; only the very first switch to
 * Arabic in a session is asynchronous. Callers that need the new language in
 * effect before continuing (tests, mostly) await the returned promise.
 */
@Injectable({ providedIn: 'root' })
export class LangService {
  private readonly doc        = inject(DOCUMENT);
  private readonly platformId = inject(PLATFORM_ID);
  private readonly config     = inject(ATTOME_CONFIG);
  private readonly transloco  = inject(TranslocoService);
  private readonly load       = inject(CATALOG_LOAD);
  private readonly registry   = inject(LayerCatalogRegistry);

  private readonly storageKey = `${this.config.portalKey ?? 'attome'}-lang`;

  /** Languages whose catalog has been handed to Transloco. */
  private readonly registered = new Set<Lang>();
  /** The most recent set() target — a slower, older request must not win. */
  private requested: Lang = 'en';
  /** NGB-5.2a — one Arabic load per layer; a failed one is dropped so it retries. */
  private readonly layerAr = new Map<LayerCatalog, Promise<void>>();
  /** Loads a route may wait on (`catalogsReady`). */
  private readonly inflight = new Set<Promise<unknown>>();
  /** Bumped on every late catalog merge so templates re-read their keys. */
  private readonly catalogVersion = signal(0);

  readonly current = signal<Lang>('en');
  readonly isRtl   = computed(() => this.current() === 'ar');
  /** For Intl.NumberFormat/DateTimeFormat — never pass `current()` to those directly. */
  readonly intlLocale = computed(() => INTL_LOCALE[this.current()]);

  /**
   * Settles once the saved language (if any) is applied with its catalog
   * loaded. Never rejects: a failed Arabic chunk leaves the app in English.
   *
   * NGB-1.9 / D-668: the wait is bounded by
   * `FIRST_RENDER_BOOT_TIMEOUT_MS`. A stalled Arabic chunk (a wedged proxy, a
   * flaky network, a stale service worker) used to hold an Arabic user on a
   * blank page indefinitely. Past the deadline the app paints in English, the
   * load keeps running, and Arabic is applied when it arrives — unless the
   * user switched away in the meantime (`switchTo`'s `requested` guard).
   */
  readonly ready: Promise<void>;

  constructor() {
    // English is bundled with the package. Register it synchronously so the
    // first template render never exposes untranslated keys while the loader's
    // observable is still being resolved.
    for (const [lang, catalog] of Object.entries(EAGER_CATALOGS)) {
      this.transloco.setTranslation(catalog, lang);
      this.registered.add(lang as Lang);
    }
    for (const layer of this.registry.layers) this.mergeEn(layer);
    this.registry.listen(layer => this.addLayer(layer));
    if (!isPlatformBrowser(this.platformId)) {
      this.ready = Promise.resolve();
      return;
    }
    let saved: string | null = null;
    try { saved = localStorage.getItem(this.storageKey); } catch { /* private mode */ }
    this.apply('en');
    this.ready = saved === 'ar'
      ? raceBootDeadline(this.switchTo('ar', false))
      : Promise.resolve();
  }

  /**
   * Switch language and persist the choice. Synchronous when the catalog is
   * already loaded; otherwise the switch takes effect when the returned
   * promise resolves. Never rejects (a failed load keeps the current language).
   */
  set(lang: Lang): Promise<void> {
    return this.switchTo(lang, true);
  }

  toggle(): Promise<void> {
    return this.set(this.requested === 'en' ? 'ar' : 'en');
  }

  /** Resolve a catalog key (optionally with ICU MessageFormat params) in the active language. */
  translate(key: string, params?: Record<string, unknown>): string {
    this.catalogVersion();
    return this.transloco.translate(key, params, this.current());
  }

  /**
   * Settles once every catalog in flight — a language switch, a layer
   * registered after Arabic was active — has landed, or after
   * `FIRST_RENDER_BOOT_TIMEOUT_MS`. Never rejects (NGB-5.2a).
   */
  catalogsReady(): Promise<void> {
    return this.inflight.size ? raceBootDeadline(Promise.all(this.inflight)) : Promise.resolve();
  }

  /**
   * NGB-2.3 / OD-8 — the one place a failed API call becomes user-visible text.
   *
   * The server answers in English (`AppError::into_response`), so its `message`
   * is the right thing to show for exactly two kinds: `validation`, whose text
   * names the field to fix, and `rule_violation`, whose text says which rule
   * refused the write. Every other kind is prose about a state the UI already
   * knows, and it belongs in the catalog: `errors.<kind>`, in the active
   * language.
   *
   * Falls back to `errors.unknown` if a kind has no catalog entry, so a raw
   * key is never rendered (NGB-3.5's coverage proof extends to these).
   */
  errorText(err: Pick<ApiError, 'kind' | 'message' | 'code'> | null | undefined): string {
    const kind = err?.kind ?? 'unknown';
    const serverText = typeof err?.message === 'string' ? err.message.trim() : '';
    if ((kind === 'validation' || kind === 'rule_violation') && serverText) return serverText;

    // A client-synthesised error carries its own catalog code
    // (`too_many_pages`, NGB-3.3) because no `kind` describes it.
    const code = typeof err?.code === 'string' ? err.code : '';
    if (code) {
      const byCode = this.translate(`errors.${code}`);
      if (byCode !== `errors.${code}`) return byCode;
    }

    const key = `errors.${kind}`;
    const text = this.translate(key);
    return text === key ? this.translate('errors.unknown') : text;
  }

  private switchTo(lang: Lang, persist: boolean): Promise<void> {
    this.requested = lang;
    if (persist) {
      try { localStorage.setItem(this.storageKey, lang); } catch { /* SSR / private */ }
    }
    if (this.registered.has(lang)) {
      this.apply(lang);
      return Promise.resolve();
    }
    return this.track(this.load(lang).then(
      async catalog => {
        if (!this.registered.has(lang)) {
          this.transloco.setTranslation(catalog, lang);
          this.registered.add(lang);
        }
        // Layers first, so the switch never shows a layer's English fallback.
        await Promise.all(this.registry.layers.map(layer => this.mergeAr(layer)));
        if (this.requested === lang) this.apply(lang);
      },
      (error: unknown) => {
        console.error(`[attome] the '${lang}' translation catalog failed to load; staying in '${this.current()}'.`, error);
        if (this.requested === lang) this.requested = this.current();
      },
    ));
  }

  private addLayer(layer: LayerCatalog): void {
    this.mergeEn(layer);
    if (this.registered.has('ar')) void this.track(this.mergeAr(layer));
  }

  private mergeEn(layer: LayerCatalog): void {
    this.transloco.setTranslation(layer.en, 'en', { merge: true });
    this.catalogVersion.update(v => v + 1);
  }

  /** Never rejects: a layer whose Arabic fails renders in English (OD-10). */
  private mergeAr(layer: LayerCatalog): Promise<void> {
    let load = this.layerAr.get(layer);
    if (!load) {
      load = layer.loadAr().then(
        catalog => {
          this.transloco.setTranslation(catalog, 'ar', { merge: true });
          this.catalogVersion.update(v => v + 1);
        },
        (error: unknown) => {
          this.layerAr.delete(layer);
          console.error("[attome] a layer's Arabic catalog failed to load; its screens stay in English.", error);
        },
      );
      this.layerAr.set(layer, load);
    }
    return load;
  }

  private track<T>(work: Promise<T>): Promise<T> {
    this.inflight.add(work);
    const done = () => { this.inflight.delete(work); };
    work.then(done, done);
    return work;
  }

  private apply(lang: Lang): void {
    this.current.set(lang);
    this.transloco.setActiveLang(lang);
    this.doc.documentElement.lang = lang;
    this.doc.documentElement.dir  = lang === 'ar' ? 'rtl' : 'ltr';
  }
}
