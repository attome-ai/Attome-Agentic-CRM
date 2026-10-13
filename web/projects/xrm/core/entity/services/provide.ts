import { EnvironmentProviders, makeEnvironmentProviders } from '@angular/core';
import { EntityService } from './entity.service';

/**
 * Optional — EntityService is providedIn: 'root' so this is only
 * needed if you want to override it or add future XRM-level providers.
 */
export function provideAttomeXrm(): EnvironmentProviders {
  return makeEnvironmentProviders([EntityService]);
}
