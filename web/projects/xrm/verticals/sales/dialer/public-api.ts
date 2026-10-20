// @attome/xrm/verticals/sales/dialer — the power dialer panel (D21-T11), its
// own entry point so only its route loads it.
export { DialerPanelComponent, OUTCOMES, previewLines } from './dialer-panel.component';
export type { DialerPhase, ScriptStep } from './dialer-panel.component';
export { DialerService } from './dialer.service';
export type {
  CallHandle, CallOutcomeBody, CallOutcomeSaved, CallSkipped, ClaimResult, ClaimedMember, DialRequest,
} from './dialer.service';
