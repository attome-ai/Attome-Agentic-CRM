import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { S2sClientFormComponent } from './forms/s2s-client-form/s2s-client-form.component';
import { S2sPermissionFormComponent } from './forms/s2s-permission-form/s2s-permission-form.component';
import { S2sAccessLogFormComponent } from './forms/s2s-access-log-form/s2s-access-log-form.component';

// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerS2sEntityForms(registry: EntityRouteRegistry): void {
  registry.register('s2s_client', { formComponent: S2sClientFormComponent });
  registry.register('s2s_permission', { formComponent: S2sPermissionFormComponent });
  registry.register('s2s_access_log', { formComponent: S2sAccessLogFormComponent });
}
