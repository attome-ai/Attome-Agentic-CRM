import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { integrationSystemActions } from './integration-system.actions';
import { IntegrationEventFormComponent } from './forms/integration-event-form/integration-event-form.component';
import { IntegrationSystemFormComponent } from './forms/integration-system-form/integration-system-form.component';

// 'integration_system' has its own form (SYSTEM-CHANGES.md Topic 14:
// every entity has one), scaffolded from the bundle and still to be designed
// by hand (D-773), and no bespoke list. "Test connection" is a
// selection-toolbar action.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap,
// scripts/chunk-budget.mjs). The loader that reaches this function lives in
// the app's composition root (`src/app/attome-metadata-form-loaders.ts`).
export function registerIntegrationEntityForms(registry: EntityRouteRegistry): void {
  registry.register('integration_system', {
    formComponent:    IntegrationSystemFormComponent,
    selectionActions: integrationSystemActions(),
  });
  registry.register('integration_event', { formComponent: IntegrationEventFormComponent });
}
