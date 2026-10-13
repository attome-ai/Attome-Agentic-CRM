import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { EaApplicationFormComponent } from './forms/ea-application-form/ea-application-form.component';
import { EaCapabilityFormComponent } from './forms/ea-capability-form/ea-capability-form.component';
import { EaSystemFormComponent } from './forms/ea-system-form/ea-system-form.component';
import { EaTechnologyFormComponent } from './forms/ea-technology-form/ea-technology-form.component';

// The enterprise-architecture vertical's entity forms (verticals/enterprise-architecture/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerEnterpriseArchitectureEntityForms(registry: EntityRouteRegistry): void {
  registry.register('ea_application', { formComponent: EaApplicationFormComponent });
  registry.register('ea_capability', { formComponent: EaCapabilityFormComponent });
  registry.register('ea_system', { formComponent: EaSystemFormComponent });
  registry.register('ea_technology', { formComponent: EaTechnologyFormComponent });
}
