// D6-T10: the sales screens metadata cannot express — the opportunity's
// Lines tab, loaded by the record tabs only when it is opened.
export { SalesApiService } from './sales-api.service';
export type {
  OpportunityHead, ProductPrice, SalesLine, SalesLinePatch, SalesLinesChanged, SyncResult,
} from './sales-api.service';
export {
  LineGridComponent, draftTotal, formatMoney, lineTotal, minorUnits,
} from './line-grid/line-grid.component';
export type { LineDraft } from './line-grid/line-grid.component';
// D7-T7: the opportunity's Team and Splits tabs.
export { SalesTeamApiService } from './team-api';
export type { PickOption, SplitRow, SplitType, SplitsOutcome, TeamAccess, TeamMember } from './team-api';
export { TEAM_FLAG, TeamPanelComponent } from './team-panel/team-panel.component';
export { SPLITS_FLAG, SplitsPanelComponent, typeTotals, unbalancedTypes } from './splits-panel/splits-panel.component';
// D3-T3: a lead's Convert tab, and bulk convert or disqualify from the lead list.
export { DISQUALIFY_REASONS, LeadConvertApiService } from './lead-convert-api';
export type {
  ConvertMode, DisqualifyReason, LeadConversionUndone, LeadConvertBody, LeadConverted, LeadConvertPreview, LeadHead,
} from './lead-convert-api';
export { LeadConvertComponent, convertBody, valueLines } from './lead-convert/lead-convert.component';
export type { MatchRow, TargetChoice } from './lead-convert/lead-convert.component';
export { LEAD_BULK_MAX, LeadBulkComponent, REASON_KEYS } from './lead-bulk/lead-bulk.component';
export type { LeadBulkResult } from './lead-bulk/lead-bulk.component';
