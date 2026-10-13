import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { OrderFormComponent } from './forms/order-form/order-form.component';
import { PriceListFormComponent } from './forms/price-list-form/price-list-form.component';
import { PriceListItemFormComponent } from './forms/price-list-item-form/price-list-item-form.component';
import { ProductFormComponent } from './forms/product-form/product-form.component';
import { QuoteFormComponent } from './forms/quote-form/quote-form.component';
import { QuoteLineFormComponent } from './forms/quote-line-form/quote-line-form.component';
import { TerritoryFormComponent } from './forms/territory-form/territory-form.component';

// The sales vertical's entity forms (verticals/sales/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
export function registerSalesEntityForms(registry: EntityRouteRegistry): void {
  registry.register('order', { formComponent: OrderFormComponent });
  registry.register('price_list', { formComponent: PriceListFormComponent });
  registry.register('price_list_item', { formComponent: PriceListItemFormComponent });
  registry.register('product', { formComponent: ProductFormComponent });
  registry.register('quote', { formComponent: QuoteFormComponent });
  registry.register('quote_line', { formComponent: QuoteLineFormComponent });
  registry.register('territory', { formComponent: TerritoryFormComponent });
}
