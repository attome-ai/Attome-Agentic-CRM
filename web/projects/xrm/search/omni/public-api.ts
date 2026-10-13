// @attome/xrm/search/omni — the omni-search box and its client (TODO-026).
//
// Split out of `@attome/xrm/search` (U13) so the shell header can render the
// record search box without importing the search module's component barrel
// (the lab, gap queue, coverage and draft queue screens) — D-314's rule that
// one entry point never pulls a sibling's screens into its own chunk.
// `@attome/xrm/search` re-exports everything here, so its public API is
// unchanged.
export { SearchService, matchQuality, isRelaxed, groupHits, formatTotal } from './search.service';
export type { SearchResponse, SearchHit, SearchTotal, MatchQuality, HitGroup } from './search.service';
export { OmniSearchComponent, DEBOUNCE_MS, MIN_QUERY_LENGTH } from './omni-search/omni-search.component';
export type { OmniSelection } from './omni-search/omni-search.component';
