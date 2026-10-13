import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { WebportalFormComponent } from './forms/webportal-form/webportal-form.component';
import { WebportalUserFormComponent } from './forms/webportal-user-form/webportal-user-form.component';

// The web portal entities' own forms (SYSTEM-CHANGES.md Topic 14: every
// entity has one), scaffolded from platform-bundles/attome-portal.json and still
// to be designed by hand (D-773). Portal administration proper stays on
// PortalAdminComponent.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerPortalEntityForms(registry: EntityRouteRegistry): void {
  registry.register('webportal', { formComponent: WebportalFormComponent });
  registry.register('webportal_user', { formComponent: WebportalUserFormComponent });
}
