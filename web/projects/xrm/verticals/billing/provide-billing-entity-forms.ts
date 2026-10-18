import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { InvoiceLineFormComponent } from './forms/invoice-line-form/invoice-line-form.component';
import { InvoiceScheduleFormComponent } from './forms/invoice-schedule-form/invoice-schedule-form.component';
import { RegionTaxRateFormComponent } from './forms/region-tax-rate-form/region-tax-rate-form.component';

// The billing pack's entity forms (roadmap F4-T15). `invoice` itself is the
// finance vertical's form, which shows billing's sections when the pack is
// installed; `region_tax_rate` is the regions pack's entity, which billing's
// tax engine reads. An entity that is not installed leaves its registration
// inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly (260KB lazy-chunk cap).
export function registerBillingEntityForms(registry: EntityRouteRegistry): void {
  registry.register('invoice_line', { formComponent: InvoiceLineFormComponent });
  registry.register('invoice_schedule', { formComponent: InvoiceScheduleFormComponent });
  registry.register('region_tax_rate', { formComponent: RegionTaxRateFormComponent });
}
