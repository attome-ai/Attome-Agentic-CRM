// G5-T1: the service workspace (home, session tabs, context panel, quick actions).
export { WorkspaceComponent } from './workspace.component';
// G11-T2: article suggestions with feedback.
export { ArticleSuggestComponent, caseQuery } from './article-suggest.component';
export type { ArticleSuggestion } from './article-suggest.component';
// G5-T2: one composer for a case.
export { ComposerComponent, matchTemplates, slashQuery } from './composer/composer.component';
export type { ComposerChannel, ReplyTemplate } from './composer/composer.component';
export { WorkspaceService, MAX_SESSIONS, openSession, sessionKey } from './workspace.service';
// G5-T3: presence and record viewers.
export { PresenceComponent, PRESENCES, toPresence } from './presence.component';
export type { Presence, Viewer } from './presence.component';
// J10-T2: the work offer toast.
export { OfferToastComponent, OFFER_POLL_MS, currentOffer, secondsLeft } from './offer-toast.component';
export type { WorkOffer, AcceptedOffer } from './offer-toast.component';
// G1-T3: the case summary panel.
export { CaseSummaryComponent, summaryText } from './case-summary.component';
export type { WorkItem, QueueSummary, ConversationSummary, RecordView, SessionTab } from './workspace.service';
