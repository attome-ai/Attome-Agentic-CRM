import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { ApiService, AuthService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FeedComponent, FeedItem, FeedPage, feedEventKey } from './feed.component';

const ME = '01900000-0000-7000-8000-00000000000a';

function item(over: Partial<FeedItem>): FeedItem {
  return {
    kind: 'post', id: 'i1', occurred_at: '2026-10-19T09:00:00Z', actor: null, body: null,
    entity: null, record_id: null, operation: null, record_name: null, ...over,
  };
}

describe('FeedComponent', () => {
  let api: { get: ReturnType<typeof vi.fn>; post: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    api = { get: vi.fn(), post: vi.fn() };
    TestBed.configureTestingModule({
      imports: [FeedComponent],
      providers: [
        provideRouter([]),
        { provide: ApiService, useValue: api },
        { provide: AuthService, useValue: { userId: signal<string | null>(ME) } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, intlLocale: () => 'en-US', current: signal('en') },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(FeedComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = <T extends HTMLElement = HTMLElement>(id: string) =>
      el.querySelector<T>(`[data-testid="${id}"]`);
    return { fixture, el, q };
  }

  it('describes record events by operation', () => {
    expect(feedEventKey('create')).toBe('feed.event.create');
    expect(feedEventKey('update')).toBe('feed.event.update');
    expect(feedEventKey('delete')).toBe('feed.event.delete');
    expect(feedEventKey(null)).toBe('feed.event.update');
  });

  it('shows posts and followed-record events, and loads older ones', () => {
    const first: FeedPage = {
      items: [
        item({ id: 'p1', body: 'Q3 numbers are in', actor: ME }),
        item({ kind: 'record_event', id: 'e1', entity: 'account', record_id: 'r1', operation: 'update', record_name: 'Acme' }),
      ],
      next_cursor: 'c1',
    };
    api.get.mockReturnValueOnce(of(first)).mockReturnValueOnce(of({ items: [item({ id: 'p0', body: 'older' })] }));
    const { fixture, el, q } = render();
    expect(api.get).toHaveBeenCalledWith('/api/v1/feed', { page_size: '25' });
    const items = el.querySelectorAll('[data-testid="feed-item"]');
    expect(items.length).toBe(2);
    expect(items[0].textContent).toContain('Q3 numbers are in');
    expect(items[0].textContent).toContain('feed.you');
    expect(items[1].textContent).toContain('Acme');

    q('feed-more')!.click();
    fixture.detectChanges();
    expect(api.get).toHaveBeenLastCalledWith('/api/v1/feed', { page_size: '25', cursor: 'c1' });
    expect(el.querySelectorAll('[data-testid="feed-item"]').length).toBe(3);
    expect(q('feed-more')).toBeNull();
  });

  it('filters by kind', () => {
    api.get.mockReturnValue(of({ items: [] }));
    const { fixture, q } = render();
    q('feed-filter-post')!.click();
    fixture.detectChanges();
    expect(api.get).toHaveBeenLastCalledWith('/api/v1/feed', { page_size: '25', kind: 'post' });
    expect(q('feed-empty')).not.toBeNull();
  });

  it('posts and reloads, or says why it could not', () => {
    api.get.mockReturnValue(of({ items: [] }));
    api.post.mockReturnValueOnce(of({ id: 'new' }))
      .mockReturnValueOnce(throwError(() => ({ kind: 'forbidden' })));
    const { fixture, q } = render();
    const draft = q<HTMLTextAreaElement>('feed-draft')!;
    draft.value = '  Hello team  ';
    draft.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    q('feed-post')!.click();
    fixture.detectChanges();
    expect(api.post).toHaveBeenCalledWith('/api/v1/feed_post', { body: 'Hello team' });
    expect(api.get).toHaveBeenCalledTimes(2);

    draft.value = 'again';
    draft.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    q('feed-post')!.click();
    fixture.detectChanges();
    expect(q('feed-post-error')?.textContent).toContain('feed.postForbidden');
  });
});
