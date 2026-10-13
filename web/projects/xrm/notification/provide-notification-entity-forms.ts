import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { NotificationTemplateFormComponent } from './notification-template/form/notification-template-form/notification-template-form.component';

// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerNotificationEntityForms(registry: EntityRouteRegistry): void {
  registry.register('notification_template', { formComponent: NotificationTemplateFormComponent });
}
