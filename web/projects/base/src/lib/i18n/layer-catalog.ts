import { EnvironmentProviders, inject, makeEnvironmentProviders, provideEnvironmentInitializer } from '@angular/core';
import type { CanActivateFn } from '@angular/router';
import type { Translation } from '@jsverse/transloco';
import { LangService } from '../lang.service';
import { LayerCatalogRegistry } from './layer-registry';

export type { LayerCatalog } from './layer-registry';

/**
 * Registers a layer's catalog where that layer mounts (NGB-5.2a, D-761, the
 * shape D-603 gave base's own Arabic catalog): at the app root for the host,
 * in a lazy route's `providers` for a library such as `@attome/xrm`. English
 * merges at once, or loads at registration when `en` is a loader (a large
 * catalog kept out of the route's chunk); Arabic loads with base's Arabic, or at registration when
 * Arabic is already active. Pair a route-level registration with
 * `canActivate: [layerCatalogsReady]` so an Arabic first render waits for it.
 */
export function provideLayerCatalog(
  en: Translation | (() => Promise<Translation>),
  loadAr: () => Promise<Translation>,
  loaders?: Readonly<Record<string, () => Promise<Translation>>>,
): EnvironmentProviders {
  const layer = { en, loadAr, loaders };
  return makeEnvironmentProviders([
    provideEnvironmentInitializer(() => inject(LayerCatalogRegistry).add(layer)),
  ]);
}

/**
 * Holds a route until every registered layer's catalog for the active
 * language has landed, bounded like the first render (D-668): past the
 * deadline the route renders with English fallbacks and updates on arrival.
 */
export const layerCatalogsReady: CanActivateFn = () =>
  inject(LangService).catalogsReady().then(() => true);
