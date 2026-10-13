import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { ServiceWorkRequestFormComponent } from './forms/work-request-form/service-work-request-form.component';
import { ServiceSlaPolicyFormComponent } from './forms/sla-policy-form/service-sla-policy-form.component';
import { ServiceTicketFormComponent } from './forms/ticket-form/service-ticket-form.component';
import { ServiceOfferingFormComponent } from './forms/offering-form/service-offering-form.component';
import { ServiceSlaClockFormComponent } from './forms/sla-clock-form/service-sla-clock-form.component';
import { ServiceWorkQueueFormComponent } from './forms/work-queue-form/service-work-queue-form.component';
import { ServiceWorkQueueMemberFormComponent } from './forms/work-queue-member-form/service-work-queue-member-form.component';
import { ServiceSlaCalculationFormComponent } from './forms/sla-calculation-form/service-sla-calculation-form.component';
import { SlaBadgeCellComponent } from './sla/sla-badge-cell/sla-badge-cell.component';

// service module had no form registration at all before this — all 7
// entities rode the generic metadata-driven EntityFormComponent. Hand-coded
// per the platform's move away from that for built-in xrm/base entities.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerServiceEntityForms(registry: EntityRouteRegistry): void {
  registry.register('service_work_request', { formComponent: ServiceWorkRequestFormComponent });
  registry.register('service_sla_policy', { formComponent: ServiceSlaPolicyFormComponent });
  // The ticket list's SLA badge: the ticket views select the SLA columns
  // (`platform-bundles/attome-service.json`) and draw `resolution_due_at` as
  // the badge.
  registry.register('service_ticket', {
    formComponent: ServiceTicketFormComponent,
    cellRenderers: { resolution_due_at: SlaBadgeCellComponent },
  });
  registry.register('service_offering', { formComponent: ServiceOfferingFormComponent });
  registry.register('service_sla_clock', { formComponent: ServiceSlaClockFormComponent });
  registry.register('service_work_queue', { formComponent: ServiceWorkQueueFormComponent });
  registry.register('service_work_queue_member', { formComponent: ServiceWorkQueueMemberFormComponent });
  registry.register('service_sla_calculation', { formComponent: ServiceSlaCalculationFormComponent });
}
