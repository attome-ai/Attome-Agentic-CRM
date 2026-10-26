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
