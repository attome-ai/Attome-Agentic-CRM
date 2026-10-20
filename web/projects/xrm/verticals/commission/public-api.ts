// @attome/xrm/verticals/commission — a seller's commission statement with
// its explanations, and the estimator panel on a deal (roadmap F10-T15).
// Its own entry point, so only the statement route or the opportunity form
// loads it.
export { CommissionStatementComponent } from './commission-statement.component';
export type { StatementRow, StatementStep } from './commission-statement.component';
export { CommissionEstimatePanelComponent } from './commission-estimate-panel.component';
export type { CommissionEstimate } from './commission-estimate-panel.component';
