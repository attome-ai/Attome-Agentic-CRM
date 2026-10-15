import { Injectable } from '@angular/core';
import type { Translation } from '@jsverse/transloco';

/**
 * One layer's own strings (NGB-5.2a, D-761): English bundled with the layer,
 * Arabic fetched the first time Arabic is needed. B20-T1: `loaders` adds the
 * layer's catalogue for any other configured language, keyed by its code.
 */
export interface LayerCatalog {
  readonly en: Translation;
  readonly loadAr: () => Promise<Translation>;
  readonly loaders?: Readonly<Record<string, () => Promise<Translation>>>;
}

/** The layer's own loader for `lang`, if it has one. */
export function layerLoader(layer: LayerCatalog, lang: string): (() => Promise<Translation>) | undefined {
  return lang === 'ar' ? layer.loadAr : layer.loaders?.[lang];
}

/**
 * Where `provideLayerCatalog()` records a layer. A dependency-free root
 * service, so registering never constructs `LangService` (and with it
 * Transloco and `ATTOME_CONFIG`) in an injector that has neither.
 */
@Injectable({ providedIn: 'root' })
export class LayerCatalogRegistry {
  private readonly all: LayerCatalog[] = [];
  private listener: ((layer: LayerCatalog) => void) | null = null;

  get layers(): readonly LayerCatalog[] {
    return this.all;
  }

  /** Idempotent per English catalog: a layer mounted on two routes registers once. */
  add(layer: LayerCatalog): void {
    if (this.all.some(l => l.en === layer.en)) return;
    this.all.push(layer);
    this.listener?.(layer);
  }

  listen(listener: (layer: LayerCatalog) => void): void {
    this.listener = listener;
  }
}
