import { computed, inject, Injectable, PLATFORM_ID, signal } from '@angular/core';
import { isPlatformBrowser } from '@angular/common';
import { DOCUMENT } from '@angular/common';
import { TranslocoService } from '@jsverse/transloco';
import { ATTOME_CONFIG } from './config';
import type { Translation } from '@jsverse/transloco';
import { CATALOG_LOAD, EAGER_CATALOGS } from './i18n/catalogs';
import { ATTOME_LANGUAGES, BASE_LANGUAGE, LanguageDef, fallbackChain } from './i18n/languages';
import { LayerCatalog, LayerCatalogRegistry, layerLoader } from './i18n/layer-registry';
import type { ApiError } from './types';

/**
 * A language code (BCP 47), one of `ATTOME_LANGUAGES` (B20-T1). English and
 * Arabic ship with the product; a deployment configures more.
 */
export type Lang = string;

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
  /** B20-T1: the languages the interface can be shown in, in picker order. */
  readonly languages          = inject(ATTOME_LANGUAGES);

  private readonly storageKey = `${this.config.portalKey ?? 'attome'}-lang`;

  /** Languages whose catalog has been handed to Transloco. */
  private readonly registered = new Set<Lang>();
  /** The most recent set() target — a slower, older request must not win. */
  private requested: Lang = BASE_LANGUAGE;
  /** NGB-5.2a — one merge of a layer into a language; a failed one is dropped so it retries. */
  private readonly layerMerges = new Map<LayerCatalog, Map<Lang, Promise<void>>>();
  /** One fetch of a layer's own catalogue per language, shared by every chain that needs it. */
  private readonly layerFetches = new Map<LayerCatalog, Map<Lang, Promise<Translation | null>>>();
  /** Loads a route may wait on (`catalogsReady`). */
  private readonly inflight = new Set<Promise<unknown>>();
  /** Bumped on every late catalog merge so templates re-read their keys. */
  private readonly catalogVersion = signal(0);

  readonly current = signal<Lang>(BASE_LANGUAGE);
  readonly isRtl   = computed(() => this.language(this.current()).dir === 'rtl');
  /**
   * For Intl.NumberFormat/DateTimeFormat — never pass `current()` to those
   * directly. Bare 'ar' resolves to Western digits under current CLDR/ICU
   * data; only a region-qualified locale such as 'ar-SA' forces the 'arab'
   * numbering system, so each language names its own.
   */
  readonly intlLocale = computed(() => this.language(this.current()).intl);

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
      this.registered.add(lang);
    }
    for (const layer of this.registry.layers) this.mergeEn(layer);
    this.registry.listen(layer => this.addLayer(layer));
    if (!isPlatformBrowser(this.platformId)) {
      this.ready = Promise.resolve();
      return;
    }
    let saved: string | null = null;
    try { saved = localStorage.getItem(this.storageKey); } catch { /* private mode */ }
    this.apply(BASE_LANGUAGE);
    this.ready = saved && saved !== BASE_LANGUAGE && this.isKnown(saved)
      ? raceBootDeadline(this.switchTo(saved, false))
      : Promise.resolve();
  }

  /**
   * Switch language and persist the choice. Synchronous when the catalog is
   * already loaded; otherwise the switch takes effect when the returned
   * promise resolves. Never rejects (a failed load keeps the current language).
   * A language that is not configured is ignored.
   */
  set(lang: Lang): Promise<void> {
    if (!this.isKnown(lang)) {
      console.error(`[attome] '${lang}' is not a configured language; staying in '${this.current()}'.`);
      return Promise.resolve();
    }
    return this.switchTo(lang, true);
  }

  /** The next configured language after the one last asked for. */
  toggle(): Promise<void> {
    const codes = this.languages.map(l => l.code);
    return this.set(codes[(codes.indexOf(this.requested) + 1) % codes.length] ?? BASE_LANGUAGE);
  }

  /** The configured language `code`, or a left-to-right stand-in for one that is not. */
  language(code: Lang): LanguageDef {
    return this.languages.find(l => l.code === code) ?? { code, dir: 'ltr', intl: code, label: code };
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
    // B20-T1: the language's own catalogue and every one it falls back to
    // before English (which Transloco's fallbackLang already covers).
    const chain = this.chain(lang);
    return this.track(Promise.all(chain.map(code => this.load(code))).then(
      async catalogs => {
        if (!this.registered.has(lang)) {
          // Most general first, so each more specific catalogue wins its keys.
          for (const catalog of [...catalogs].reverse()) {
            this.transloco.setTranslation(catalog, lang, { merge: true });
          }
          this.registered.add(lang);
        }
        // Layers first, so the switch never shows a layer's English fallback.
        await Promise.all(this.registry.layers.map(layer => this.mergeLayer(layer, lang)));
        if (this.requested === lang) this.apply(lang);
      },
      (error: unknown) => {
        console.error(`[attome] the '${lang}' translation catalog failed to load; staying in '${this.current()}'.`, error);
        if (this.requested === lang) this.requested = this.current();
      },
    ));
  }

  /** B20-T3: lays a deployment's rewordings (catalogue key to text) over `lang`. */
  applyOverrides(lang: Lang, texts: Record<string, string>): void {
    if (!Object.keys(texts).length) return;
    this.transloco.setTranslation(nestKeys(texts), lang, { merge: true });
    this.catalogVersion.update(v => v + 1);
  }

  private addLayer(layer: LayerCatalog): void {
    this.mergeEn(layer);
    for (const lang of this.registered) {
      if (lang !== BASE_LANGUAGE) void this.track(this.mergeLayer(layer, lang));
    }
  }

  private isKnown(lang: Lang): boolean {
    return this.languages.some(l => l.code === lang);
  }

  /** `lang` and the languages it falls back to before English, most specific first. */
  private chain(lang: Lang): Lang[] {
    return fallbackChain(lang, this.languages).filter(code => code !== BASE_LANGUAGE);
  }

  private mergeEn(layer: LayerCatalog): void {
    this.transloco.setTranslation(layer.en, 'en', { merge: true });
    this.catalogVersion.update(v => v + 1);
  }

  /**
   * Merges a layer's catalogues for `lang`'s chain into `lang`, most general
   * first. Never rejects: a layer whose catalogue fails renders in the next
   * language of the chain, English last (OD-10), and a later call retries.
   */
  private mergeLayer(layer: LayerCatalog, lang: Lang): Promise<void> {
    const merges = this.layerMerges.get(layer) ?? new Map<Lang, Promise<void>>();
    this.layerMerges.set(layer, merges);
    let merge = merges.get(lang);
    if (!merge) {
      const chain = this.chain(lang).filter(code => layerLoader(layer, code));
      merge = Promise.all(chain.map(code => this.fetchLayer(layer, code))).then(catalogs => {
        for (const catalog of [...catalogs].reverse()) {
          if (catalog) this.transloco.setTranslation(catalog, lang, { merge: true });
        }
        this.catalogVersion.update(v => v + 1);
        if (catalogs.includes(null)) merges.delete(lang);
      });
      merges.set(lang, merge);
    }
    return merge;
  }

  /** One layer catalogue; `null` when it failed to load (the next call retries). */
  private fetchLayer(layer: LayerCatalog, code: Lang): Promise<Translation | null> {
    const fetches = this.layerFetches.get(layer) ?? new Map<Lang, Promise<Translation | null>>();
    this.layerFetches.set(layer, fetches);
    let fetch = fetches.get(code);
    if (!fetch) {
      const loader = layerLoader(layer, code);
      fetch = (loader ? loader() : Promise.resolve({})).then(
        catalog => catalog,
        (error: unknown) => {
          fetches.delete(code);
          console.error(`[attome] a layer's '${code}' catalog failed to load; its screens fall back to the next language.`, error);
          return null;
        },
      );
      fetches.set(code, fetch);
    }
    return fetch;
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
    this.doc.documentElement.dir  = this.language(lang).dir;
  }
}

/** `{"a.b": "x"}` as `{a: {b: "x"}}`, the shape a catalogue has. */
export function nestKeys(flat: Record<string, string>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, text] of Object.entries(flat)) {
    const parts = key.split('.');
    let node = out;
    parts.forEach((part, i) => {
      if (i === parts.length - 1) {
        node[part] = text;
      } else {
        const next = node[part];
        node = (typeof next === 'object' && next !== null ? next : (node[part] = {})) as Record<string, unknown>;
      }
    });
  }
  return out;
}
