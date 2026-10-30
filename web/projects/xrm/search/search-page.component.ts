import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { entityFormRoute } from '@attome/xrm/core/entity';
import { groupHits, isRelaxed } from '@attome/xrm/search/omni';
import type { HitGroup } from '@attome/xrm/search/omni';
import {
  AskResult,
  AskingSearchResponse,
  FacetCount,
  SearchHit,
  SearchPageService,
} from './services/search-page.service';

/** Where the recent searches are kept, in this browser only. */
export const RECENT_SEARCHES_KEY = 'attome-search-recent';
/** How many recent searches are kept. */
export const MAX_RECENT = 8;

/** One entity group with its count over every result, not only this page. */
export interface CountedGroup extends HitGroup {
  count: number;
}

/**
 * Groups `hits` by entity in rank order and counts each group from the
 * entity facet when the server sent one (it counts every result the caller
 * may see), else from the page. Pure.
 */
export function countedGroups(hits: SearchHit[], entityFacet: FacetCount[] | undefined): CountedGroup[] {
  const counts = new Map((entityFacet ?? []).map(f => [f.value, f.count]));
  return groupHits(hits).map(g => ({ ...g, count: counts.get(g.entity) ?? g.hits.length }));
}

/** `q` with an `entity:` filter for `entity`, replacing any there already. Pure. */
export function withEntityFilter(q: string, entity: string | null): string {
  const rest = q
    .split(/\s+/)
    .filter(t => t && !/^(entity|type):/i.test(t))
    .join(' ');
  return entity ? `${rest} entity:${entity}`.trim() : rest;
}

/** The entity whose search hits are attached files (A25-T6). */
export const DOCUMENT_ENTITY = 'attome_document';

/** A file address that opens a PDF viewer at `page`. Pure. */
export function urlAtPage(url: string, page: number): string {
  return `${url.split('#')[0]}#page=${page}`;
}

/** `recent` with `q` first, once, at most [`MAX_RECENT`]. Pure. */
export function pushRecent(recent: string[], q: string): string[] {
  const trimmed = q.trim();
  if (!trimmed) return recent;
  return [trimmed, ...recent.filter(r => r !== trimmed)].slice(0, MAX_RECENT);
}

/**
 * The search page (A25-T11): results grouped by entity with counts, the
 * facet sidebar (entity filters the search; owner and month show counts),
 * the "ask" mode with its parsed filter and direct answer, explanations for
 * builders, recent searches, and saving a search with an alert.
 */
@Component({
  selector: 'xrm-search-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  templateUrl: './search-page.component.html',
  styleUrls: ['./search-page.component.css'],
})
export class SearchPageComponent {
  private readonly search = inject(SearchPageService);
  private readonly lang = inject(LangService);

  protected readonly query = signal('');
  protected readonly ask = signal(false);
  protected readonly explain = signal(false);
  protected readonly loading = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly response = signal<AskingSearchResponse | null>(null);
  protected readonly recent = signal<string[]>(readRecent());

  protected readonly saveName = signal('');
  protected readonly saveAlert = signal(false);
  protected readonly saved = signal(false);

  protected readonly groups = computed<CountedGroup[]>(() => {
    const r = this.response();
    return r ? countedGroups(r.items, r.facets?.entity) : [];
  });
  protected readonly facets = computed(() => this.response()?.facets ?? null);
  protected readonly askResult = computed<AskResult | null>(() => this.response()?.ask ?? null);
  protected readonly relaxed = computed(() => isRelaxed(this.response()?.items ?? []));
  protected readonly activeEntity = computed(() => {
    const m = /(?:^|\s)(?:entity|type):(\S+)/i.exec(this.query());
    return m ? m[1] : null;
  });

  protected formRoute(entity: string): string[] {
    return entityFormRoute(entity);
  }

  /** Whether a hit is an attached file the query matched on a known page. */
  protected hasPage(hit: SearchHit): boolean {
    return hit.entity_logicalname === DOCUMENT_ENTITY && !!hit.page;
  }

  /** Opens a document hit's file at the page the query matched (A25-T6). */
  protected openAtPage(hit: SearchHit): void {
    const page = hit.page;
    if (!page) return;
    this.search.documentFileUrl(hit.record_id).subscribe({
      next: res => window.open(urlAtPage(res.download_url, page), '_blank', 'noopener'),
      error: () => this.error.set(this.lang.translate('searchPage.openFailed')),
    });
  }

  protected onQuery(event: Event): void {
    this.query.set((event.target as HTMLInputElement).value);
  }

  protected onSaveName(event: Event): void {
    this.saveName.set((event.target as HTMLInputElement).value);
  }

  toggleAsk(): void {
    this.ask.update(v => !v);
  }

  protected toggleExplain(): void {
    this.explain.update(v => !v);
  }

  toggleAlert(): void {
    this.saveAlert.update(v => !v);
  }

  /** Runs the search for the current query. */
  run(): void {
    const q = this.query().trim();
    if (!q) return;
    this.loading.set(true);
    this.error.set(null);
    this.saved.set(false);
    this.search.search(q, { ask: this.ask(), explain: this.explain(), pageSize: 50 }).subscribe({
      next: r => {
        this.response.set(r);
        this.loading.set(false);
        this.recent.set(pushRecent(this.recent(), q));
        writeRecent(this.recent());
      },
      error: (e: ApiError) => {
        this.loading.set(false);
        this.error.set(e.message ?? this.lang.translate('searchPage.failed'));
      },
    });
  }

  /** Filters by an entity facet, or clears the filter for the one already chosen. */
  protected filterEntity(entity: string): void {
    const next = this.activeEntity() === entity ? null : entity;
    this.query.set(withEntityFilter(this.query(), next));
    this.run();
  }

  protected runRecent(q: string): void {
    this.query.set(q);
    this.run();
  }

  saveSearch(): void {
    const name = this.saveName().trim();
    const q = this.query().trim();
    if (!name || !q) return;
    this.search.saveSearch(name, q, this.saveAlert()).subscribe({
      next: () => this.saved.set(true),
      error: (e: ApiError) => this.error.set(e.message ?? this.lang.translate('searchPage.saveFailed')),
    });
  }

  /** The filter the words became, as one readable line. */
  protected filterText(ask: AskResult): string {
    const f = ask.filter;
    if (!f) return '';
    return f.where ? `${f.entity}: ${JSON.stringify(f.where)}` : f.entity;
  }

  protected percent(value: number): string {
    return `${Math.round(value * 1000) / 10}`;
  }
}

function readRecent(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_SEARCHES_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string').slice(0, MAX_RECENT) : [];
  } catch {
    return [];
  }
}

function writeRecent(recent: string[]): void {
  try {
    localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(recent));
  } catch {
    /* blocked storage: recent searches are a convenience */
  }
}
