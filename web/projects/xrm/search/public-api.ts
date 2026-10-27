// @attome/xrm/search — the omni-search box and its client (TODO-026).
//
// Its own secondary entry point, like every other feature here, so a route that
// never renders search does not pull it in.
// The box and its client live in `@attome/xrm/search/omni` (U13), re-exported
// here so this entry point's public API is unchanged.
export {
  SearchService, matchQuality, isRelaxed, groupHits, formatTotal,
  OmniSearchComponent, DEBOUNCE_MS, MIN_QUERY_LENGTH,
} from '@attome/xrm/search/omni';
export type {
  SearchResponse, SearchHit, SearchTotal, MatchQuality, HitGroup, OmniSelection,
} from '@attome/xrm/search/omni';
export { SearchLabComponent } from './lab/lab.component';
// A25-T11: the search page and search administration.
export { SearchPageComponent } from './search-page.component';
export { SearchSettingsComponent } from './search-settings.component';
export { SearchPageService } from './services/search-page.service';
export type { AskResult, AskingSearchResponse } from './services/search-page.service';
export { GapQueueComponent } from './gaps/gap-queue.component';
export { KnowledgeCoverageComponent } from './coverage/knowledge-coverage.component';
export { DraftQueueComponent } from './drafts/draft-queue.component';
export { KnowledgeService } from './services/knowledge.service';
export type { GapTopic, CollectionCoverage, IndexerStatus } from './services/knowledge.service';

// Hand-coded forms (moving off the generic metadata-driven EntityFormComponent
// for the platform's own built-in entities — see xrm/audit and xrm/notification
// for the established pattern).
export { registerSearchEntityForms } from './provide-search-entity-forms';
// Y14-T4: this screen's own catalogue.
export { searchLabAr, searchLabEn } from './search-lab.i18n';
