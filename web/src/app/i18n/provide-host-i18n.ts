import { EnvironmentProviders } from '@angular/core';
import { provideLayerCatalog } from '@attome/base';
import { hostEn } from './en.catalog';

const loadHostAr = () => import('./ar.catalog').then(m => m.hostAr);

/** The host app's own screens' strings (NGB-5.2b, D-761); registered at the root. */
export function provideHostI18n(): EnvironmentProviders {
  return provideLayerCatalog(hostEn, loadHostAr);
}
