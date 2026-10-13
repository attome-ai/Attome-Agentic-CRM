import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { AccountFormComponent } from './forms/account-form/account-form.component';
import { ActivityFormComponent } from './forms/activity-form/activity-form.component';
import { ContactFormComponent } from './forms/contact-form/contact-form.component';
import { LeadFormComponent } from './forms/lead-form/lead-form.component';
import { OpportunityFormComponent } from './forms/opportunity-form/opportunity-form.component';

// The crm vertical's entity forms (verticals/crm/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerCrmEntityForms(registry: EntityRouteRegistry): void {
  registry.register('account', { formComponent: AccountFormComponent });
  registry.register('activity', { formComponent: ActivityFormComponent });
  registry.register('contact', { formComponent: ContactFormComponent });
  registry.register('lead', { formComponent: LeadFormComponent });
  registry.register('opportunity', { formComponent: OpportunityFormComponent });
}
