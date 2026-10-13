import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { AssetFormComponent } from './forms/asset-form/asset-form.component';
import { LocationFormComponent } from './forms/location-form/location-form.component';

// The asset-management vertical's entity forms (verticals/asset-management/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerAssetManagementEntityForms(registry: EntityRouteRegistry): void {
  registry.register('asset', { formComponent: AssetFormComponent });
  registry.register('location', { formComponent: LocationFormComponent });
}
