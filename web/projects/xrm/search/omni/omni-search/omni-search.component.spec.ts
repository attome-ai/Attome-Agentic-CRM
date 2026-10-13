import { ComponentFixture, TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { Observable, Subject, of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { OmniSearchComponent, DEBOUNCE_MS, MIN_QUERY_LENGTH } from './omni-search.component';
import {
  SearchHit,
  SearchResponse,
  SearchService,
  formatTotal,
  groupHits,
  isRelaxed,
  matchQuality,
} from '../search.service';

function hit(over: Partial<SearchHit> = {}): SearchHit {
  return {
    entity_logicalname: 'account',
    record_id: crypto.randomUUID(),
    title: 'ACME Trading LLC',
    subtitle: null,
    score: 1,
    matched_legs: ['R3.lexical'],
    ...over,
  };
}

function response(over: Partial<SearchResponse> = {}): SearchResponse {
  return {
    items: [hit()],
    total: { kind: 'exact', value: 1 },
    page: 1,
    page_size: 10,
    has_more: false,
    route: 'lexical',
    degraded: [],
    ...over,
  } as SearchResponse;
}

/** A stub that records every query and lets a test control each response. */
class StubSearch {
  readonly queries: string[] = [];
  responder: (q: string) => Observable<SearchResponse> = () => of(response());
  search(q: string): Observable<SearchResponse> {
    this.queries.push(q);
    return this.responder(q);
  }
}

function mount(): { fixture: ComponentFixture<OmniSearchComponent>; component: OmniSearchComponent; api: StubSearch } {
  const api = new StubSearch();
  TestBed.configureTestingModule({
    imports: [OmniSearchComponent],
    providers: [
      { provide: SearchService, useValue: api },
      { provide: LangService, useValue: { translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(OmniSearchComponent);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, api };
}

describe('OmniSearchComponent', () => {
  let ctx: ReturnType<typeof mount>;

  beforeEach(() => {
    // Vitest fake timers rather than Angular's `fakeAsync`: this workspace is
    // zoneless, so `zone-testing` is not loaded and `tick()` has nothing to
    // drive. rxjs's `debounceTime` schedules on the async scheduler, which is
    // `setInterval` underneath, so vi's timers control it directly.
    vi.useFakeTimers();
    TestBed.resetTestingModule();
    ctx = mount();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('debounces within the specified window and issues one request', () => {
    ctx.component.onInput('a');
    ctx.component.onInput('ac');
    ctx.component.onInput('acm');
    ctx.component.onInput('acme');
    vi.advanceTimersByTime(DEBOUNCE_MS - 1);
    expect(ctx.api.queries).toEqual([]);
    vi.advanceTimersByTime(1);
    expect(ctx.api.queries).toEqual(['acme']);
  });

  it(`does not query below ${MIN_QUERY_LENGTH} characters`, () => {
    ctx.component.onInput('a');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    expect(ctx.api.queries).toEqual([]);
  });

  /**
   * **The classic typeahead bug.** With `mergeMap`, a slow response for "ac"
   * arriving after the fast one for "acme" overwrites correct results with
   * stale ones — invisible on a fast network, constant on a slow one, and so it
   * survives development and ships. `switchMap` cancels the earlier request;
   * this asserts the late response is never applied.
   */
  it('discards a slow response that a newer query has superseded', () => {
    const slow = new Subject<SearchResponse>();
    ctx.api.responder = (q) => (q === 'ac' ? slow.asObservable() : of(response({ items: [hit({ title: 'Right' })] })));

    ctx.component.onInput('ac');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    ctx.component.onInput('acme');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    expect(ctx.component.flat()[0].title).toBe('Right');

    // The stale response lands late. It must not be applied.
    slow.next(response({ items: [hit({ title: 'Stale' })] }));
    slow.complete();
    expect(ctx.component.flat()[0].title).toBe('Right');
  });

  /**
   * An error must clear the list, not leave the previous query's hits under the
   * new query's text — stale results a user believes are current are worse than
   * none.
   */
  it('clears results when a search fails rather than showing the previous ones', () => {
    ctx.component.onInput('acme');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    expect(ctx.component.flat().length).toBe(1);

    ctx.api.responder = () => throwError(() => new Error('boom'));
    ctx.component.onInput('zenith');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    expect(ctx.component.flat()).toEqual([]);
    expect(ctx.component.searching()).toBe(false);
  });

  it('closes the panel immediately when the box is cleared, without waiting a debounce', () => {
    ctx.component.onInput('acme');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    expect(ctx.component.open()).toBe(true);

    ctx.component.onInput('');
    expect(ctx.component.open()).toBe(false);
    expect(ctx.component.flat()).toEqual([]);
    vi.advanceTimersByTime(DEBOUNCE_MS);
  });

  it('marks a result set that was relaxed to fuzzy matching', () => {
    ctx.api.responder = () => of(response({ items: [hit({ matched_legs: ['R5.fuzzy'] })] }));
    ctx.component.onInput('acne');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    expect(ctx.component.relaxed()).toBe(true);
  });

  it('does not mark a set relaxed when any hit matched exactly', () => {
    ctx.api.responder = () =>
      of(response({ items: [hit({ matched_legs: ['R1.exact_key'] }), hit({ matched_legs: ['R5.fuzzy'] })] }));
    ctx.component.onInput('inv-9001');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    expect(ctx.component.relaxed()).toBe(false);
  });

  it('surfaces degradation rather than swallowing it', () => {
    ctx.api.responder = () => of(response({ degraded: ['R5.fuzzy'] }));
    ctx.component.onInput('acme');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    expect(ctx.component.degraded()).toEqual(['R5.fuzzy']);
    ctx.fixture.detectChanges();
    const text = (ctx.fixture.nativeElement as HTMLElement).textContent ?? '';
    // The LangService stub echoes catalog keys, so the notice renders its key.
    expect(text).toContain('omniSearch.degraded');
  });

  describe('keyboard navigation', () => {
    beforeEach(() => {
      ctx.api.responder = () =>
        of(response({ items: [hit({ title: 'One' }), hit({ title: 'Two' }), hit({ title: 'Three' })] }));
      ctx.component.onInput('acme');
      vi.advanceTimersByTime(DEBOUNCE_MS);
    });

    it('starts with no active option, so Enter cannot select by accident', () => {
      expect(ctx.component.active()).toBe(-1);
      let emitted = 0;
      ctx.component.selected.subscribe(() => emitted++);
      ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'Enter' }));
      expect(emitted).toBe(0);
    });

    it('wraps in both directions', () => {
      const down = () => ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
      down();
      expect(ctx.component.active()).toBe(0);
      down();
      down();
      expect(ctx.component.active()).toBe(2);
      down();
      expect(ctx.component.active()).toBe(0);
      ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'ArrowUp' }));
      expect(ctx.component.active()).toBe(2);
    });

    it('exposes the active option through aria-activedescendant', () => {
      expect(ctx.component.activeId()).toBeNull();
      ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
      expect(ctx.component.activeId()).toBe('omni-opt-0');
    });

    it('Escape closes without selecting', () => {
      let emitted = 0;
      ctx.component.selected.subscribe(() => emitted++);
      ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
      ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'Escape' }));
      expect(ctx.component.open()).toBe(false);
      expect(emitted).toBe(0);
    });

    it('emits rank and impression id with the selection', () => {
      ctx.api.responder = () =>
        of(
          response({
            items: [hit({ title: 'One' }), hit({ title: 'Two' })],
            impression_id: 'imp-1',
          }),
        );
      ctx.component.onInput('acme trading');
      vi.advanceTimersByTime(DEBOUNCE_MS);

      let seen: { rank: number; impressionId: string | null } | null = null;
      ctx.component.selected.subscribe((s) => (seen = { rank: s.rank, impressionId: s.impressionId }));
      ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
      ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
      ctx.component.onKeydown(new KeyboardEvent('keydown', { key: 'Enter' }));
      expect(seen).toEqual({ rank: 1, impressionId: 'imp-1' });
    });
  });

  /**
   * The rendered markup must satisfy the combobox pattern. A search box that
   * only works with a mouse is one a keyboard user cannot use at all, and the
   * failure is invisible to everyone who is not using a screen reader.
   */
  it('renders the ARIA combobox pattern', () => {
    ctx.component.onInput('acme');
    vi.advanceTimersByTime(DEBOUNCE_MS);
    ctx.fixture.detectChanges();

    const el = ctx.fixture.nativeElement as HTMLElement;
    const input = el.querySelector('input')!;
    expect(input.getAttribute('role')).toBe('combobox');
    expect(input.getAttribute('aria-expanded')).toBe('true');
    expect(input.getAttribute('aria-controls')).toBe('omni-listbox');
    expect(input.getAttribute('aria-autocomplete')).toBe('list');

    const listbox = el.querySelector('#omni-listbox')!;
    expect(listbox.getAttribute('role')).toBe('listbox');
    expect(el.querySelectorAll('[role="option"]').length).toBe(1);
    // Group headings are decorative: announcing "account" as an option would
    // put an unselectable item in the listbox's navigation order.
    expect(el.querySelector('.omni__group-label')!.getAttribute('aria-hidden')).toBe('true');
  });
});

describe('search helpers', () => {
  it('classifies match quality by leg prefix, not equality', () => {
    // Prefix matching so a future `R3.lexical_v2` does not silently reclassify
    // every lexical hit as approximate — which would have the UI telling users
    // their exact matches are guesses.
    expect(matchQuality(hit({ matched_legs: ['R3.lexical_v2'] }))).toBe('lexical');
    expect(matchQuality(hit({ matched_legs: ['R1.exact_key', 'R5.fuzzy'] }))).toBe('exact');
    expect(matchQuality(hit({ matched_legs: ['R5.fuzzy'] }))).toBe('approximate');
    expect(matchQuality(hit({ matched_legs: [] }))).toBe('approximate');
  });

  it('never reports an empty result set as relaxed', () => {
    // "No exact matches — relaxed to closest spellings" over zero results
    // states something false about a search that simply found nothing.
    expect(isRelaxed([])).toBe(false);
  });

  it('orders groups by their best hit, never alphabetically', () => {
    const groups = groupHits([
      hit({ entity_logicalname: 'ticket', title: 'best' }),
      hit({ entity_logicalname: 'account', title: 'second' }),
      hit({ entity_logicalname: 'ticket', title: 'third' }),
    ]);
    expect(groups.map((g) => g.entity)).toEqual(['ticket', 'account']);
    expect(groups[0].hits.length).toBe(2);
  });

  it('renders an approximate total as approximate', () => {
    // The backend returns `at_least` when the match set hit the candidate
    // ceiling, so the true count is unknown and larger. Printing "500 results"
    // states something false.
    expect(formatTotal({ kind: 'at_least', value: 500 })).toBe('500+ results');
    expect(formatTotal({ kind: 'exact', value: 3 })).toBe('3 results');
    expect(formatTotal({ kind: 'exact', value: 1 })).toBe('1 result');
  });
});
