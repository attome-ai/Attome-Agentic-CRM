import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  SearchPageComponent,
  countedGroups,
  pushRecent,
  withEntityFilter,
} from './search-page.component';
import { AskingSearchResponse, SearchHit, SearchPageService } from './services/search-page.service';

function hit(entity: string, title: string): SearchHit {
  return {
    entity_logicalname: entity,
    record_id: crypto.randomUUID(),
    title,
    subtitle: null,
    score: 1,
    matched_legs: ['R3.lexical'],
  } as SearchHit;
}

function response(over: Partial<AskingSearchResponse> = {}): AskingSearchResponse {
  return {
    items: [hit('account', 'Al-Faisal Trading'), hit('contact', 'Sara Al-Faisal'), hit('account', 'Faisal Holding')],
    total: { kind: 'exact', value: 3 },
    page: 1,
    page_size: 50,
    has_more: false,
    route: 'lexical',
    degraded: [],
    facets: {
      entity: [{ value: 'account', count: 7 }, { value: 'contact', count: 1 }],
      owner: [],
      modified_month: [{ value: '2026-10', count: 8 }],
    },
    ...over,
  } as AskingSearchResponse;
}

describe('SearchPageComponent', () => {
  let api: { search: ReturnType<typeof vi.fn>; saveSearch: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    try { localStorage.clear(); } catch { /* blocked storage */ }
    api = { search: vi.fn(() => of(response())), saveSearch: vi.fn(() => of({})) };
    TestBed.configureTestingModule({
      imports: [SearchPageComponent],
      providers: [
        provideRouter([]),
        { provide: SearchPageService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function mount() {
    const fixture = TestBed.createComponent(SearchPageComponent);
    fixture.detectChanges();
    return fixture;
  }

  function type(fixture: ReturnType<typeof mount>, q: string): void {
    const input = fixture.nativeElement.querySelector('.search-page__input') as HTMLInputElement;
    input.value = q;
    input.dispatchEvent(new Event('input'));
    fixture.componentInstance.run();
    fixture.detectChanges();
  }

  it('groups results by entity', () => {
    const fixture = mount();
    type(fixture, 'faisal');
    const groups = Array.from(fixture.nativeElement.querySelectorAll('[data-group]')) as HTMLElement[];
    expect(groups.map(g => g.querySelector('[data-group-entity]')?.textContent?.trim())).toEqual(['account', 'contact']);
    // The count is the facet's, over every result, not this page's two.
    expect(groups[0].querySelector('[data-group-count]')?.textContent?.trim()).toBe('7');
    expect(groups[0].querySelectorAll('.search-page__hit').length).toBe(2);
    expect(api.search).toHaveBeenCalledWith('faisal', { ask: false, explain: false, pageSize: 50 });
  });

  it('filters by an entity facet and clears it again', () => {
    const fixture = mount();
    type(fixture, 'faisal');
    const facet = fixture.nativeElement.querySelector('[data-facet-entity]') as HTMLButtonElement;
    facet.click();
    expect(api.search).toHaveBeenLastCalledWith('faisal entity:account', expect.anything());
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-facet-entity]') as HTMLButtonElement).click();
    expect(api.search).toHaveBeenLastCalledWith('faisal', expect.anything());
  });

  it('shows the parsed filter and the direct answer in ask mode', () => {
    api.search.mockReturnValue(of(response({
      ask: {
        status: 'parsed',
        filter: { entity: 'service_case', where: { kind: 'compare', field: 'status', op: 'eq', value: 'open' } },
        answer: { answer: 'Two cases are open.', citations: [{ entity: 'service_case', record_id: crypto.randomUUID(), title: 'Late delivery' }] },
      },
    })));
    const fixture = mount();
    fixture.componentInstance.toggleAsk();
    type(fixture, 'how many open complaints?');
    expect(api.search).toHaveBeenCalledWith('how many open complaints?', expect.objectContaining({ ask: true }));
    expect(fixture.nativeElement.querySelector('[data-filter]')?.textContent).toContain('service_case');
    expect(fixture.nativeElement.querySelector('[data-answer]')?.textContent).toContain('Two cases are open.');
  });

  it('keeps recent searches, newest first, once each', () => {
    expect(pushRecent(['a', 'b'], 'b')).toEqual(['b', 'a']);
    expect(pushRecent([], '  ')).toEqual([]);
    expect(pushRecent(['1', '2', '3', '4', '5', '6', '7', '8'], 'new')).toHaveLength(8);
  });

  it('replaces an entity filter in the query', () => {
    expect(withEntityFilter('acme entity:contact', 'account')).toBe('acme entity:account');
    expect(withEntityFilter('acme type:account', null)).toBe('acme');
    expect(countedGroups([hit('account', 'x')], undefined)[0].count).toBe(1);
  });

  it('saves the search with its alert', () => {
    const fixture = mount();
    type(fixture, 'faisal');
    const name = fixture.nativeElement.querySelector('.search-page__save input[type=text]') as HTMLInputElement;
    name.value = 'Faisal';
    name.dispatchEvent(new Event('input'));
    fixture.componentInstance.toggleAlert();
    fixture.componentInstance.saveSearch();
    expect(api.saveSearch).toHaveBeenCalledWith('Faisal', 'faisal', true);
  });
});
