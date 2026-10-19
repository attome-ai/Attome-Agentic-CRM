import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ArticleSuggestComponent, caseQuery } from './article-suggest.component';

const ARTICLES = [
  { item_id: 'k1', title: 'Reset a VPN token', passage: 'Open the portal and…' },
  { item_id: 'k2', title: 'Crawled page', passage: 'From the website' },
];

describe('ArticleSuggestComponent', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = { get: vi.fn(() => of({ items: ARTICLES })), post: vi.fn() };
    TestBed.configureTestingModule({
      imports: [ArticleSuggestComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
  });

  function render(text: string) {
    const fixture = TestBed.createComponent(ArticleSuggestComponent);
    fixture.componentRef.setInput('text', text);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const all = (id: string) => el.querySelectorAll<HTMLElement>(`[data-testid="${id}"]`);
    return { fixture, el, all };
  }

  it('builds the query from the case title and description', () => {
    expect(caseQuery('  VPN down ', 'Token expired')).toBe('VPN down Token expired');
    expect(caseQuery(null, '')).toBe('');
    expect(caseQuery('x'.repeat(600), null).length).toBe(500);
  });

  it('suggests articles for the case text', () => {
    const { all } = render('VPN token expired');
    expect(api.get).toHaveBeenCalledWith('/api/v1/search/knowledge', { q: 'VPN token expired', limit: '3' });
    expect(all('article-suggestion').length).toBe(2);
  });

  it('asks nothing for a too-short text', () => {
    const { el } = render('hi');
    expect(api.get).not.toHaveBeenCalled();
    expect(el.querySelector('[data-testid="article-none"]')).not.toBeNull();
  });

  it('records helpful and not-helpful, and says when an item takes no feedback', () => {
    api.post.mockImplementation((_path: string, body: { item_id: string }) =>
      body.item_id === 'k1' ? of({ recorded: true }) : throwError(() => ({ kind: 'not_found' })));
    const { fixture, el, all } = render('VPN token expired');
    all('article-useful')[0].click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/content/knowledge-feedback', { item_id: 'k1', useful: true });
    expect(all('article-suggestion')[0].textContent).toContain('articleSuggest.thanks');

    all('article-not-useful')[0].click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenLastCalledWith('/api/v1/content/knowledge-feedback', { item_id: 'k2', useful: false });
    expect(el.querySelector('[data-testid="article-no-feedback"]')).not.toBeNull();
  });
});
