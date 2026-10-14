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
export { AiSpendComponent, forecastOver, spendState, type SpendLine, type SpendReport } from './spend/spend.component';
export type { ScopeSwitch } from './admin/scope-switches/ai-scope-switches.component';
