import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents } from '@attome/base';

/** `GET /api/v1/search`'s response, straight from the generated contract. */
export type SearchResponse = ApiComponents['schemas']['SearchResponse'];
export type SearchHit = ApiComponents['schemas']['SearchHit'];
export type SearchTotal = ApiComponents['schemas']['Total'];

/** How a hit was found, derived from `matched_legs`. */
export type MatchQuality = 'exact' | 'lexical' | 'prefix' | 'approximate';

/**
 * Hits for one entity, in the order the backend ranked them.
 *
 * Grouping is presentational only — it never reorders across groups by name.
 * Sorting groups alphabetically would demote the single best hit below an
 * unrelated group whose entity happens to start with "a", which is the one
 * thing a typeahead must never do.
 */
export interface HitGroup {
  entity: string;
  hits: SearchHit[];
  /** Rank of this group's best hit in the flat list. Drives group order. */
  bestRank: number;
}

/**
 * The typed client for the search endpoint (TODO-026).
 *
 * **Nothing here requests highlighting.** `ts_headline` re-parses and re-ranks
 * every returned document server-side, which is affordable on a results page
 * and not on a keystroke. The typeahead shows the stored title and subtitle;
 * highlighting belongs to a full results page if it is ever wanted at all.
 */
@Injectable({ providedIn: 'root' })
export class SearchService {
  private readonly api = inject(ApiService);

  search(q: string, opts?: { pageSize?: number; audience?: 'human' | 'agent' }): Observable<SearchResponse> {
    const params: Record<string, string> = { q };
    if (opts?.pageSize) params['page_size'] = String(opts.pageSize);
    if (opts?.audience) params['audience'] = opts.audience;
    return this.api.get<SearchResponse>('/api/v1/search', params);
  }
}

/**
 * Which leg found this hit, reduced to something a user can be told.
 *
 * Leg ids are stable (`R1.exact_key`, `R2.prefix`, `R3.lexical`, `R5.fuzzy`)
 * and are matched by prefix rather than equality, so adding `R3.lexical_v2`
 * does not silently reclassify every hit as `approximate` — the failure mode
 * of an equality check here is that the UI starts telling users their exact
 * matches are guesses.
 */
export function matchQuality(hit: SearchHit): MatchQuality {
  const legs = hit.matched_legs ?? [];
  if (legs.some((l) => l.startsWith('R1.'))) return 'exact';
  if (legs.some((l) => l.startsWith('R3.'))) return 'lexical';
  if (legs.some((l) => l.startsWith('R2.'))) return 'prefix';
  return 'approximate';
}

/**
 * Whether the whole result set is approximate — every hit came from fuzzy
 * matching alone.
 *
 * This is what the "relaxed to…" marker reports. Stating it matters: a user
 * who typed a name and got a *near* match with no indication will read it as
 * an exact one and act on the wrong record. Per-hit badges are not a
 * substitute, because the reflex is to click the first row, not to read it.
 */
export function isRelaxed(hits: SearchHit[]): boolean {
  return hits.length > 0 && hits.every((h) => matchQuality(h) === 'approximate');
}

/** Groups hits by entity, preserving backend rank order within and between groups. */
export function groupHits(hits: SearchHit[]): HitGroup[] {
  const groups = new Map<string, HitGroup>();
  hits.forEach((hit, rank) => {
    const existing = groups.get(hit.entity_logicalname);
    if (existing) existing.hits.push(hit);
    else groups.set(hit.entity_logicalname, { entity: hit.entity_logicalname, hits: [hit], bestRank: rank });
  });
  return [...groups.values()].sort((a, b) => a.bestRank - b.bestRank);
}

/**
 * How the total is shown to a user.
 *
 * `at_least` must never be rendered as a plain number. The backend returns it
 * when the match set hit the candidate ceiling, so the true count is unknown
 * and larger; printing "500 results" states something false, and a user
 * comparing that against a report will conclude the search is broken rather
 * than that the label was approximate.
 */
export function formatTotal(total: SearchTotal): string {
  const n = total.value;
  if (total.kind === 'at_least') return `${n}+ results`;
  return n === 1 ? '1 result' : `${n} results`;
}
