import { EnvironmentProviders } from '@angular/core';
import { provideLayerCatalog } from '@attome/base';
import { xrmEn } from './en.catalog';

const loadXrmAr = () => import('@attome/xrm/core/i18n-ar').then(m => m.xrmAr);

/**
 * Registers xrm's catalog. Put it in the `providers` of the route that mounts
 * xrm screens, with `canActivate: [layerCatalogsReady]` so an Arabic session's
 * first xrm render already has xrm's Arabic.
 */
export function provideXrmI18n(): EnvironmentProviders {
  return provideLayerCatalog(xrmEn, loadXrmAr);
}
