// @attome/xrm/marketing/deliverability — the deliverability dashboard, the
// alert guidance panel and the pre-send check panel (E6-T13), their own entry
// point so only their route loads them.
export {
  DeliverabilityDashboardComponent, chartMax, linePoints, rateSeries,
} from './deliverability-dashboard.component';
export type { RateMetric, RateSeries } from './deliverability-dashboard.component';
export { GuidancePanelComponent } from './guidance-panel.component';
export { PrecheckPanelComponent, orderFindings } from './precheck-panel.component';
export { DeliverabilityService } from './deliverability.service';
export type {
  BlocklistStatus, DeliverabilityAlert, DeliverabilityOverview, DmarcShare, PrecheckBody,
  PrecheckFinding, PrecheckReport, ProviderDay, SendTotals,
} from './deliverability.service';
