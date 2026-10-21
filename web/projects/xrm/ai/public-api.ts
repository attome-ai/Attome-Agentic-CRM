// @attome/xrm/ai — AI form fields and components (MODULE_AI, TODO-038).
//
// Its own secondary entry point, like every other feature here, so a route
// that does not render an AI surface never pulls the code in. That matters
// more than usual for this one: a deployment with the AI kill-switch off
// should ship no AI behaviour at all, and lazy loading makes that true of the
// bundle as well as the runtime.
export { AiActionsService } from './services/ai-actions.service';
export type {
  ActionSummary,
  ActionOutcome,
  Provenance,
  SuggestionDecision,
} from './services/ai-actions.service';
export { registerAiEntityForms } from './provide-ai-entity-forms';
export { AiPlaygroundComponent } from './playground/ai-playground.component';
// C6 (D-556) — the live-session supervisor screen ('ai/sessions'), the read
// side of capability administration: it lists running sessions with the
// ceiling and grants they started with, and pauses/resumes/kills them through
// the three registered agent.* actions. The policy and capability-pack forms
// are not exported here — they are reached through the entity router, which
// loads `registerAiEntityForms` and never needs a named import.
export { AiAgentSessionsComponent } from './admin/agent-sessions/ai-agent-sessions.component';
export { AiScopeSwitchesComponent, SCOPE_KINDS } from './admin/scope-switches/ai-scope-switches.component';
export { AiAgentAutonomyComponent, AUTONOMY_LEVELS, raisesConsequential } from './autonomy/agent-autonomy.component';
export type { AutonomyEntry, AutonomyLevel, AutonomyRow } from './autonomy/agent-autonomy.component';
export { AiPendingActionsComponent } from './autonomy/pending-actions.component';
export { AiAgentTrialComponent, percent } from './autonomy/agent-trial.component';
export type { ActionAgreement, DifferentDecision, TrialReport } from './autonomy/agent-trial.component';
export type { DeferredAction } from './autonomy/pending-actions.component';
export { AiGovernanceComponent, approvedShare } from './governance/governance.component';
export { AiMcpServersComponent, MCP_TIERS } from './mcp-servers/mcp-servers.component';
export { AiStatusComponent, overall, type AiStatus } from './status/status.component';
export { AiSpendComponent, forecastOver, spendState, type SpendLine, type SpendReport } from './spend/spend.component';
export type { ScopeSwitch } from './admin/scope-switches/ai-scope-switches.component';
// AI4-T7: my follow-ups ('ai/follow-ups').
export { AiFollowupsComponent, ageInDays, type AiFollowupItem } from './followups/ai-followups.component';
// AI6-T7: the meeting brief and notes panels, for the meeting form to place.
export { AiMeetingBriefComponent, textDir } from './meeting/ai-meeting-brief.component';
export { AiMeetingNotesComponent, valueText } from './meeting/ai-meeting-notes.component';
export {
  AiMeetingService,
  checkedIndexes,
  parseNotesItems,
  toMeetingNotes,
} from './meeting/ai-meeting.service';
export type {
  MeetingActionItem,
  MeetingBrief,
  MeetingNotes,
  MeetingNotesQueued,
  MeetingRecordUpdate,
  NotesRecord,
} from './meeting/ai-meeting.service';
// AI5-T7: the invoice's collections panel, placed by the invoice form.
export { AiCollectionsPanelComponent } from './collections/ai-collections-panel.component';
export { AiCollectionsService, awaitsReview, stillOpen } from './collections/ai-collections.service';
export type {
  CollectionsReminder,
  PaymentPromise,
  PromiseChanged,
} from './collections/ai-collections.service';
