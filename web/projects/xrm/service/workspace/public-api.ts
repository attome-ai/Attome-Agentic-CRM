// G5-T1: the service workspace (home, session tabs, context panel, quick actions).
export { WorkspaceComponent } from './workspace.component';
// G11-T2: article suggestions with feedback.
export { ArticleSuggestComponent, caseQuery } from './article-suggest.component';
export type { ArticleSuggestion } from './article-suggest.component';
// G5-T2: one composer for a case.
export { ComposerComponent, matchTemplates, slashQuery } from './composer/composer.component';
export type { ComposerChannel, ReplyTemplate } from './composer/composer.component';
export { WorkspaceService, MAX_SESSIONS, openSession, sessionKey } from './workspace.service';
export type { WorkItem, QueueSummary, ConversationSummary, RecordView, SessionTab } from './workspace.service';
