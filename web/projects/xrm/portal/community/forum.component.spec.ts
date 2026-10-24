import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ForumComponent, visibleItems } from './forum.component';
import { ForumService, type ForumPost, type PortalRecord } from './forum.service';

const rec = <T>(id: string, data: T, created_at = '2026-10-01T00:00:00Z'): PortalRecord<T> => ({ id, row_version: 1, created_at, data });

describe('visibleItems (G13-T2)', () => {
  it('leaves rejected items out', () => {
    const items: PortalRecord<ForumPost>[] = [
      rec('a', { moderation_status: 'published' }),
      rec('b', { moderation_status: 'rejected' }),
      rec('c', { moderation_status: 'pending' }),
    ];
    expect(visibleItems(items).map(i => i.id)).toEqual(['a', 'c']);
  });
});

describe('ForumComponent (G13-T2)', () => {
  const current = signal('en');
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    current.set('en');
    svc = {
      categories: vi.fn(() => of([
        rec('c2', { name: 'Billing', name_ar: 'الفوترة', sort_order: 2 }),
        rec('c1', { name: 'Getting started', name_ar: 'البداية', sort_order: 1 }),
        rec('c3', { name: 'Hidden', sort_order: 0, is_portal_visible: false }),
      ])),
      threads: vi.fn(() => of([
        rec('t1', { title: 'How do I export?', status: 'open', moderation_status: 'published' }, '2026-10-02T00:00:00Z'),
        rec('t2', { title: 'Welcome', status: 'answered', is_pinned: true, moderation_status: 'published' }, '2026-09-01T00:00:00Z'),
        rec('t3', { title: 'Spam', moderation_status: 'rejected' }),
      ])),
      thread: vi.fn(() => of(rec('t1', { title: 'How do I export?', status: 'answered', body: 'Where is it?', accepted_post_ref: 'p2' }))),
      posts: vi.fn(() => of([
        rec('p1', { body: 'Try settings', author_name: 'Huda' }, '2026-10-02T01:00:00Z'),
        rec('p2', { body: 'Use the export button', author_name: 'Staff', is_staff: true }, '2026-10-02T02:00:00Z'),
      ])),
      ideas: vi.fn(() => of([
        rec('i1', { title: 'Dark mode', vote_count: 3, status: 'planned' }),
        rec('i2', { title: 'Hijri dates', vote_count: 9, status: 'new' }),
      ])),
      createThread: vi.fn(() => of(rec('t9', {}))),
      reply: vi.fn(() => of(rec('p9', {}))),
      createIdea: vi.fn(() => of(rec('i9', {}))),
      vote: vi.fn(() => of({})),
      me: vi.fn(() => of({ id: 'portal-user-1' })),
    };
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [ForumComponent],
      providers: [
        { provide: ForumService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current, errorText: () => 'failed', isRtl: () => current() === 'ar' },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(ForumComponent);
    fixture.componentRef.setInput('keyword', 'acme');
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  const q = (root: HTMLElement, id: string) => [...root.querySelectorAll(`[data-testid="${id}"]`)] as HTMLElement[];

  it('shows visible categories in order and opens the first', () => {
    const root: HTMLElement = render().nativeElement;
    expect(q(root, 'forum-category').map(b => b.textContent?.trim())).toEqual(['Getting started', 'Billing']);
    expect(svc['threads']).toHaveBeenCalledWith('acme', 'c1');
    // Pinned first, the rejected one left out.
    expect(q(root, 'forum-thread-row').map(r => r.getAttribute('data-id'))).toEqual(['t2', 't1']);
  });

  it('opens a thread with the accepted answer first and replies', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (q(root, 'forum-thread-row')[1].querySelector('button') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc['thread']).toHaveBeenCalledWith('acme', 't1');
    const posts = q(root, 'forum-post');
    expect(posts[0].getAttribute('data-id')).toBe('p2');
    expect(posts[0].querySelector('[data-testid="forum-accepted"]')).not.toBeNull();
    (fixture.componentInstance as unknown as { replyBody: { set(v: string): void } }).replyBody.set('Thanks!');
    fixture.detectChanges();
    (root.querySelector('[data-testid="forum-reply"]') as HTMLButtonElement).click();
    expect(svc['reply']).toHaveBeenCalledWith('acme', 't1', 'Thanks!');
  });

  it('starts a thread with only its content fields', () => {
    const fixture = render();
    const c = fixture.componentInstance as unknown as { newTitle: { set(v: string): void }; newBody: { set(v: string): void } };
    c.newTitle.set(' Question ');
    c.newBody.set('Body');
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-testid="forum-new-thread"]') as HTMLButtonElement).click();
    expect(svc['createThread']).toHaveBeenCalledWith('acme', 'c1', 'Question', 'Body');
  });

  it('lists ideas by votes and votes once as the portal user', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-testid="forum-tab-ideas"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(q(root, 'forum-idea').map(i => i.getAttribute('data-id'))).toEqual(['i2', 'i1']);
    (q(root, 'forum-vote-idea')[0] as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(svc['vote']).toHaveBeenCalledWith('acme', { idea: 'i2' }, 'portal-user-1', 1);
    expect((q(root, 'forum-vote-idea')[0] as HTMLButtonElement).disabled).toBe(true);
  });

  it('asks a signed-out visitor to sign in', () => {
    svc['categories'].mockReturnValue(throwError(() => ({ status: 401, kind: 'unauthorized' })));
    const root: HTMLElement = render().nativeElement;
    expect(root.querySelector('[data-testid="forum-signed-out"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="forum-error"]')).toBeNull();
  });

  it('mirrors in Arabic with Arabic category names', () => {
    current.set('ar');
    const root: HTMLElement = render().nativeElement;
    expect(root.querySelector('[data-testid="forum"]')?.getAttribute('dir')).toBe('rtl');
    expect(q(root, 'forum-category')[0].textContent?.trim()).toBe('البداية');
  });
});
