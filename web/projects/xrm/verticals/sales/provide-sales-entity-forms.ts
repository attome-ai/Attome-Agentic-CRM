import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { EntityRouteRegistry, SelectionAction } from '@attome/xrm/core/entity';
import { defer } from 'rxjs';
import { OrderFormComponent } from './forms/order-form/order-form.component';
import { PriceListFormComponent } from './forms/price-list-form/price-list-form.component';
import { PriceListItemFormComponent } from './forms/price-list-item-form/price-list-item-form.component';
import { ProductFormComponent } from './forms/product-form/product-form.component';
import { QuoteFormComponent } from './forms/quote-form/quote-form.component';
import { QuoteLineFormComponent } from './forms/quote-line-form/quote-line-form.component';
import { TerritoryFormComponent } from './forms/territory-form/territory-form.component';
import { CallAnalysisFormComponent } from './forms/call-analysis-form/call-analysis-form.component';
import { CallTrackerFormComponent } from './forms/call-tracker-form/call-tracker-form.component';
import { PointsModelFormComponent } from './forms/points-model-form/points-model-form.component';
import { PointsRuleFormComponent } from './forms/points-rule-form/points-rule-form.component';
import { PointsScoreFormComponent } from './forms/points-score-form/points-score-form.component';
import { CallFindingFormComponent } from './forms/call-finding-form/call-finding-form.component';
import { CallScorecardFormComponent } from './forms/call-scorecard-form/call-scorecard-form.component';
import { CallScorecardAnswerFormComponent } from './forms/call-scorecard-answer-form/call-scorecard-answer-form.component';
import { CallCommentFormComponent } from './forms/call-comment-form/call-comment-form.component';
import { CallLibraryFormComponent } from './forms/call-library-form/call-library-form.component';
import { CallLibraryItemFormComponent } from './forms/call-library-item-form/call-library-item-form.component';
import { CallDailyAggregateFormComponent } from './forms/call-daily-aggregate-form/call-daily-aggregate-form.component';

// The sales vertical's entity forms (verticals/sales/bundle.json).
// SYSTEM-CHANGES.md Topic 14: every entity has its own form in code; these are
// bundle scaffolds (scripts/bundle-to-form-component.mjs) on the shared base
// form, still to be designed by hand (D-773). The vertical's entities exist
// only where its bundle is installed, so an unused registration is inert.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why (260KB lazy-chunk cap).
/** D21-T11: "Start dialer" on one active call list opens the dialer for it. */
export function callListActions(): SelectionAction[] {
  const router = inject(Router);
  return [{
    key: 'sales-start-dialer',
    labelKey: 'salesDialer.start',
    style: 'primary',
    isVisible: rows => rows.length === 1 && rows[0]['status'] === 'active',
    run: id => defer(() => router.navigate(['/xrm/sales/dialer', id])),
  }];
}

export function registerSalesEntityForms(registry: EntityRouteRegistry): void {
  registry.register('call_list', { selectionActions: callListActions() });
  registry.register('order', { formComponent: OrderFormComponent });
  registry.register('price_list', { formComponent: PriceListFormComponent });
  registry.register('price_list_item', { formComponent: PriceListItemFormComponent });
  registry.register('product', { formComponent: ProductFormComponent });
  registry.register('quote', { formComponent: QuoteFormComponent });
  registry.register('quote_line', { formComponent: QuoteLineFormComponent });
  registry.register('territory', { formComponent: TerritoryFormComponent });
  registry.register('call_analysis', { formComponent: CallAnalysisFormComponent });
  registry.register('call_tracker', { formComponent: CallTrackerFormComponent });
  registry.register('points_model', { formComponent: PointsModelFormComponent });
  registry.register('points_rule', { formComponent: PointsRuleFormComponent });
  registry.register('points_score', { formComponent: PointsScoreFormComponent });
  registry.register('call_finding', { formComponent: CallFindingFormComponent });
  registry.register('call_scorecard', { formComponent: CallScorecardFormComponent });
  registry.register('call_scorecard_answer', { formComponent: CallScorecardAnswerFormComponent });
  registry.register('call_comment', { formComponent: CallCommentFormComponent });
  registry.register('call_library', { formComponent: CallLibraryFormComponent });
  registry.register('call_library_item', { formComponent: CallLibraryItemFormComponent });
  registry.register('call_daily_aggregate', { formComponent: CallDailyAggregateFormComponent });
}
