import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { ApiService, LangService, LiveChannel } from '@attome/base';
import { Observable, defer, of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  NOTIFICATION_POLL_MAX_BACKOFF_MS,
  NOTIFICATION_POLL_MS,
  NotificationBellComponent,
  XrmNotif,
  groupNotifications,
  notificationPollDelay,
} from './notification-bell.component';

interface PollResponse { notifications: XrmNotif[]; unread_count: number }

/**
 * Records every poll and lets a test decide each response.
 *
 * The component builds its `HttpClient.post(...)` pipeline once per
 * `pollLoop()` and leans on `repeat()` resubscribing to that same cold
 * Observable to redispatch the request — genuine `HttpClient` behaviour,
 * where every subscription is a fresh network call. `defer()` here is what
 * makes the stub honor that: counting inside the deferred factory ties
 * `polls` to subscriptions (real polls), not to how many times `post()` the
 * function was called (once, ever).
 */
class StubApi {
  polls = 0;
  responder: () => Observable<PollResponse> = () => of({ notifications: [], unread_count: 0 });
  post(url: string): Observable<unknown> {
    if (url.endsWith('/notification/poll')) {
      return defer(() => { this.polls += 1; return this.responder(); });
    }
    return of({});
  }
}

// `document.visibilityState` is a read-only accessor on `Document.prototype`;
// an own configurable property on the instance shadows it and is deleted in
// `afterEach` so the prototype's getter is back for every other spec.
let visibility: DocumentVisibilityState = 'visible';

function setVisibility(state: DocumentVisibilityState): void {
  visibility = state;
  document.dispatchEvent(new Event('visibilitychange'));
}

function mount(api = new StubApi()): { fixture: ComponentFixture<NotificationBellComponent>; component: NotificationBellComponent; api: StubApi } {
  TestBed.configureTestingModule({
    imports: [NotificationBellComponent],
    providers: [
      provideRouter([]),
      { provide: ApiService, useValue: api },
      { provide: LangService, useValue: { current: signal('en'), set: vi.fn(), translate: (key: string) => key } },
    ],
  });
  const fixture = TestBed.createComponent(NotificationBellComponent);
  fixture.detectChanges();
  return { fixture, component: fixture.componentInstance, api };
}

describe('NotificationBellComponent polling (T7-4)', () => {
  beforeEach(() => {
    // Vitest fake timers rather than Angular's `fakeAsync`: the workspace is
    // zoneless, so `tick()` has nothing to drive. rxjs's `timer` schedules on
    // the async scheduler (`setTimeout` underneath), which vi controls.
    vi.useFakeTimers();
    visibility = 'visible';
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => visibility });
    TestBed.resetTestingModule();
  });

  afterEach(() => {
    Reflect.deleteProperty(document, 'visibilityState');
    vi.useRealTimers();
  });

  it('refreshes at once when the live channel says the inbox changed (J11-T1)', () => {
    const { api } = mount();
    expect(api.polls).toBe(1);
    TestBed.inject(LiveChannel).notifications.next(2);
    expect(api.polls).toBe(2);
  });

  it('polls immediately and then on the steady cadence while visible', () => {
    const { api } = mount();
    expect(api.polls).toBe(1);

    vi.advanceTimersByTime(NOTIFICATION_POLL_MS - 1);
    expect(api.polls).toBe(1);
    vi.advanceTimersByTime(1);
    expect(api.polls).toBe(2);
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS);
    expect(api.polls).toBe(3);
  });

  it('applies a successful poll to the signals', () => {
    const api = new StubApi();
    const n: XrmNotif = { id: 'n1', title: 't', message: 'm', type: 0, isRead: false, timestamp: 0 };
    api.responder = () => of({ notifications: [n], unread_count: 1 });
    const { component } = mount(api);

    expect(component.notifications()).toEqual([n]);
    expect(component.unreadCount()).toBe(1);
  });

  it('issues no request while the document is hidden', () => {
    visibility = 'hidden';
    const { api } = mount();
    expect(api.polls).toBe(0);

    vi.advanceTimersByTime(NOTIFICATION_POLL_MS * 3);
    expect(api.polls).toBe(0);
  });

  it('stops polling when the document goes hidden', () => {
    const { api } = mount();
    expect(api.polls).toBe(1);

    setVisibility('hidden');
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS * 3);
    expect(api.polls).toBe(1);
  });

  it('polls immediately when the document becomes visible again', () => {
    visibility = 'hidden';
    const { api } = mount();
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS);
    expect(api.polls).toBe(0);

    // No timer advance: the refresh must be immediate, not at the next tick.
    setVisibility('visible');
    expect(api.polls).toBe(1);

    vi.advanceTimersByTime(NOTIFICATION_POLL_MS);
    expect(api.polls).toBe(2);
  });

  it('ignores a visibilitychange that does not change the state', () => {
    const { api } = mount();
    expect(api.polls).toBe(1);

    setVisibility('visible');
    expect(api.polls).toBe(1);
  });

  it('lengthens the next interval after each consecutive failure', () => {
    const api = new StubApi();
    api.responder = () => throwError(() => new Error('boom'));
    mount(api);
    expect(api.polls).toBe(1);

    // One failure: the next poll waits 2x, not 1x.
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS);
    expect(api.polls).toBe(1);
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS);
    expect(api.polls).toBe(2);

    // Two failures: 4x.
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS * 3);
    expect(api.polls).toBe(2);
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS);
    expect(api.polls).toBe(3);
  });

  it('resets the cadence after a success', () => {
    const api = new StubApi();
    let fail = true;
    api.responder = () => (fail ? throwError(() => new Error('boom')) : of({ notifications: [], unread_count: 0 }));
    mount(api);
    expect(api.polls).toBe(1);

    fail = false;
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS * 2);
    expect(api.polls).toBe(2);

    // Back on the steady cadence.
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS);
    expect(api.polls).toBe(3);
  });

  it('stops polling once the component is destroyed', () => {
    const { fixture, api } = mount();
    expect(api.polls).toBe(1);

    fixture.destroy();
    vi.advanceTimersByTime(NOTIFICATION_POLL_MS * 3);
    expect(api.polls).toBe(1);
  });
});

describe('notification groups (J11-T2)', () => {
  const notif = (id: string, type: number, route: string | undefined, isRead = false): XrmNotif =>
    ({ id, title: id, message: '', type, isRead, timestamp: 0, route });

  it('groups by kind and record, newest first', () => {
    const groups = groupNotifications([
      notif('a', 0, '/xrm/account/1'),
      notif('b', 2, '/xrm/account/1'),
      notif('c', 0, '/xrm/account/1', true),
      notif('d', 0, undefined),
      notif('e', 0, undefined),
    ]);
    expect(groups.map(g => g.items.map(n => n.id))).toEqual([['a', 'c'], ['b'], ['d'], ['e']]);
    expect(groups[0].latest.id).toBe('a');
    expect(groups[0].unread).toBe(1);
  });

  it('opening a group reads all of it and follows its link', () => {
    const api = new StubApi();
    const posts: string[] = [];
    const post = api.post.bind(api);
    api.post = (url: string) => { posts.push(url); return post(url); };
    const { fixture, component } = mount(api);
    component.notifications.set([notif('a', 0, '/xrm/account/1'), notif('c', 0, '/xrm/account/1')]);
    component.unreadCount.set(2);
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigateByUrl').mockResolvedValue(true);
    expect(component.groups().length).toBe(1);
    component.onGroupClick(component.groups()[0]);
    fixture.detectChanges();
    expect(component.unreadCount()).toBe(0);
    expect(posts.filter(u => u.endsWith('/notification/read')).length).toBe(2);
    expect(navigate).toHaveBeenCalledWith('/xrm/account/1');
  });
});

describe('notificationPollDelay', () => {
  it('doubles per consecutive failure and caps at five minutes', () => {
    expect([0, 1, 2, 3, 4, 5, 10].map(notificationPollDelay)).toEqual([
      NOTIFICATION_POLL_MS,
      NOTIFICATION_POLL_MS * 2,
      NOTIFICATION_POLL_MS * 4,
      NOTIFICATION_POLL_MS * 8,
      NOTIFICATION_POLL_MAX_BACKOFF_MS,
      NOTIFICATION_POLL_MAX_BACKOFF_MS,
      NOTIFICATION_POLL_MAX_BACKOFF_MS,
    ]);
  });
});
