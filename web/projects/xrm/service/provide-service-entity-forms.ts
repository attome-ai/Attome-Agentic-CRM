import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { ServiceWorkRequestFormComponent } from './forms/work-request-form/service-work-request-form.component';
import { ServiceSlaPolicyFormComponent } from './forms/sla-policy-form/service-sla-policy-form.component';
import { ServiceTicketFormComponent } from './forms/ticket-form/service-ticket-form.component';
import { ServiceOfferingFormComponent } from './forms/offering-form/service-offering-form.component';
import { ServiceSlaClockFormComponent } from './forms/sla-clock-form/service-sla-clock-form.component';
import { ServiceWorkQueueFormComponent } from './forms/work-queue-form/service-work-queue-form.component';
import { ServiceWorkQueueMemberFormComponent } from './forms/work-queue-member-form/service-work-queue-member-form.component';
import { ServiceSlaCalculationFormComponent } from './forms/sla-calculation-form/service-sla-calculation-form.component';
import { SupplierSlaClockFormComponent } from './forms/supplier-sla-clock-form/supplier-sla-clock-form.component';
import { ServiceEscalationRuleFormComponent } from './forms/escalation-rule-form/service-escalation-rule-form.component';
import { ServiceConversionMapFormComponent } from './forms/conversion-map-form/service-conversion-map-form.component';
import { ServiceCatalogFormComponent } from './forms/catalog-form/service-catalog-form.component';
import { ServiceCategoryFormComponent } from './forms/category-form/service-category-form.component';
import { ServiceOfferingVersionFormComponent } from './forms/offering-version-form/service-offering-version-form.component';
import { ServiceRequestItemFormComponent } from './forms/request-item-form/service-request-item-form.component';
import { ServiceFulfilmentTaskFormComponent } from './forms/fulfilment-task-form/service-fulfilment-task-form.component';
import { ServiceOrderGuideFormComponent } from './forms/order-guide-form/service-order-guide-form.component';
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
  registry.register('supplier_sla_clock', { formComponent: SupplierSlaClockFormComponent });
  registry.register('service_escalation_rule', { formComponent: ServiceEscalationRuleFormComponent });
  registry.register('service_conversion_map', { formComponent: ServiceConversionMapFormComponent });
  registry.register('service_catalog', { formComponent: ServiceCatalogFormComponent });
  registry.register('service_category', { formComponent: ServiceCategoryFormComponent });
  registry.register('service_offering_version', { formComponent: ServiceOfferingVersionFormComponent });
  registry.register('service_request_item', { formComponent: ServiceRequestItemFormComponent });
  registry.register('service_fulfilment_task', { formComponent: ServiceFulfilmentTaskFormComponent });
  registry.register('service_order_guide', { formComponent: ServiceOrderGuideFormComponent });
}
