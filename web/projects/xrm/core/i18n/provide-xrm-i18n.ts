import { EnvironmentProviders } from '@angular/core';
import { provideLayerCatalog, type LayerCatalog } from '@attome/base';

/** A catalog as base's i18n takes it. */
type Catalog = Awaited<ReturnType<LayerCatalog['loadAr']>>;

const loadXrmEn = () => import('@attome/xrm/core/i18n-en').then(m => m.xrmEn as Catalog);
const loadXrmAr = () => import('@attome/xrm/core/i18n-ar').then(m => m.xrmAr);

/**
 * Registers xrm's catalog. Put it in the `providers` of the route that mounts
 * xrm screens, with `canActivate: [layerCatalogsReady]` so the first xrm render
 * already has xrm's English (and Arabic, in an Arabic session).
 *
 * `en` passes the English catalog in directly instead of loading it, for a
 * test that renders at once without the route guard.
 */
export function provideXrmI18n(en?: Catalog): EnvironmentProviders {
  return provideLayerCatalog(en ?? loadXrmEn, loadXrmAr);
}
