import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { BudgetFormComponent } from './forms/budget-form/budget-form.component';
import { CostCenterFormComponent } from './forms/cost-center-form/cost-center-form.component';
import { ExpenseFormComponent } from './forms/expense-form/expense-form.component';
import { InvoiceFormComponent } from './forms/invoice-form/invoice-form.component';
import { PaymentFormComponent } from './forms/payment-form/payment-form.component';

// The finance vertical's entity forms (verticals/finance/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerFinanceEntityForms(registry: EntityRouteRegistry): void {
  registry.register('budget', { formComponent: BudgetFormComponent });
  registry.register('cost_center', { formComponent: CostCenterFormComponent });
  registry.register('expense', { formComponent: ExpenseFormComponent });
  registry.register('invoice', { formComponent: InvoiceFormComponent });
  registry.register('payment', { formComponent: PaymentFormComponent });
}
