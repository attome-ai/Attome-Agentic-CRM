// @attome/xrm/verticals/billing — the billing screens (roadmap F4-T16): an
// account's statement and the receivables ageing; and the billing pack's
// entity forms (F4-T15). Its own entry point, so only a route to one of
// them loads it.
export { AccountStatementComponent, monthStart } from './statements/account-statement.component';
export { AgeingReportComponent } from './statements/ageing-report.component';
export {
  AGEING_BUCKETS, BillingService,
  type AccountStatement, type AgeingRow, type AgeingTotals, type CurrencyStatement, type StatementEntry,
} from './data/billing.service';
export { formatAmount, minorUnits } from './data/money';
export { registerBillingEntityForms } from './provide-billing-entity-forms';
export { ZatcaOnboardingComponent, canOnboard } from './zatca/zatca-onboarding.component';
export type { EinvoiceDevice, NewEinvoiceDevice } from './zatca/zatca-onboarding.component';
