import { DOCUMENT } from '@angular/common';
import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, computed, effect, inject, OnInit, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { ApiService, TranslatePipe, LiveChannel } from '@attome/base';
import { WebPushService } from '../services/web-push.service';
import {
  EMPTY, Observable, catchError, distinctUntilChanged, fromEvent, map, of, repeat, startWith, switchMap, tap, timer,
} from 'rxjs';

export interface XrmNotif {
  id:        string;
  title:     string;
  message:   string;
  type:      number;   // 0=info 1=success 2=warning 3=error
  isRead:    boolean;
  timestamp: number;   // unix epoch seconds
  route?:    string;
}

/**
 * J11-T2: notifications of one kind about one record, shown as one row: the
 * newest, with how many more there are.
 */
export interface NotifGroup {
  key:    string;
  latest: XrmNotif;
  items:  XrmNotif[];
  unread: number;
}

/**
 * Groups notifications by kind and record (the link they open), newest
 * first as the server sends them. One without a link stays on its own.
 */
export function groupNotifications(list: XrmNotif[]): NotifGroup[] {
  const groups: NotifGroup[] = [];
  const byKey = new Map<string, NotifGroup>();
  for (const n of list) {
    const key = n.route ? `${n.type}|${n.route}` : `one|${n.id}`;
    let group = byKey.get(key);
    if (!group) {
      group = { key, latest: n, items: [], unread: 0 };
      byKey.set(key, group);
      groups.push(group);
    }
    group.items.push(n);
    if (!n.isRead) group.unread += 1;
  }
  return groups;
}

/** The steady-state poll cadence while the tab is visible and the API is healthy. */
export const NOTIFICATION_POLL_MS = 30_000;

/** The longest gap the failure backoff grows to (T7-4). */
export const NOTIFICATION_POLL_MAX_BACKOFF_MS = 300_000;

/**
 * The delay before the next poll, given how many polls in a row have failed.
 * Doubles per consecutive failure from the steady-state cadence — 30 s, 60 s,
 * 120 s, 240 s — and caps at {@link NOTIFICATION_POLL_MAX_BACKOFF_MS}, so a
 * backend outage sees one request every five minutes per open tab rather than
 * every thirty seconds. A single success resets the count.
 */
export function notificationPollDelay(consecutiveFailures: number): number {
  return Math.min(NOTIFICATION_POLL_MS * 2 ** consecutiveFailures, NOTIFICATION_POLL_MAX_BACKOFF_MS);
}

/**
 * Whether the document is currently visible, as a stream: emits the current
 * state on subscribe, then again on every change, deduplicated. Feed it into
 * `switchMap` to run a polling loop only while the user can actually see the
 * result — a background tab issuing requests it will never render is pure
 * load on the API (T7-4).
 *
 * This is the canonical copy; `ProfilerComponent` keeps a private duplicate
 * because it lives in a different ng-packagr entry point and this component is
 * not on `@attome/xrm/shell`'s barrel (importing the barrel to reach it would
 * pull the whole shell into the profiler chunk, D-314). If a third caller
 * appears, lift this into `@attome/base`.
 */
export function pageVisible$(doc: Document): Observable<boolean> {
  return fromEvent(doc, 'visibilitychange').pipe(
    startWith(null),
    map(() => doc.visibilityState === 'visible'),
    distinctUntilChanged(),
  );
}

/**
 * The header's notification bell and its dropdown (D-315).
 *
 * Extracted whole from `ShellComponent`, state and all: the poll loop, the
 * read/clear calls and the outside-click close were never coupled to anything
 * else in the shell. Nothing coordinates this with `ProfileMenuComponent`
 * either, and none is needed — opening the profile menu is a document click
 * outside this host, which this component's own handler already closes on.
 * That is exactly the behaviour the shell's combined handler used to produce.
 *
 * Polling (T7-4): runs only while the document is visible — hiding the tab
 * tears the loop down (cancelling any in-flight poll), and showing it again
 * polls immediately rather than waiting out the remainder of an interval.
 * Consecutive failures back off exponentially (`notificationPollDelay`); a
 * success resets the cadence.
 */
@Component({
  selector:   'attome-notification-bell',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  host: { '(document:click)': 'onDocumentClick($event)' },
  styleUrls: ['../header-dropdown.css', './notification-bell.component.css'],
  templateUrl: './notification-bell.component.html',
})
export class NotificationBellComponent implements OnInit {
  private readonly api        = inject(ApiService);
  private readonly router     = inject(Router);
  private readonly host       = inject(ElementRef<HTMLElement>);
  private readonly document   = inject(DOCUMENT);
  private readonly destroyRef = inject(DestroyRef);
  private readonly live       = inject(LiveChannel);
  /** B19-T2: browser push and the installed app's badge. */
  readonly push               = inject(WebPushService);
  readonly pushMessage        = signal<string | null>(null);

  readonly notifications = signal<XrmNotif[]>([]);
  readonly unreadCount   = signal(0);
  readonly isOpen        = signal(false);
  /** J11-T2: the notifications by kind and record. */
  readonly groups        = computed(() => groupNotifications(this.notifications()));

  constructor() {
    // B19-T2: the installed app's icon shows the unread count.
    effect(() => this.push.setBadge(this.unreadCount()));
    this.push.watchClicks();
  }

  /** B19-T2: turns browser notifications on or off for this browser. */
  async togglePush(): Promise<void> {
    this.pushMessage.set(null);
    try {
      if (this.push.enabled()) {
        await this.push.disable();
      } else {
        this.pushMessage.set(await this.push.enable() ? 'webPush.on' : 'webPush.refused');
      }
    } catch {
      this.pushMessage.set('webPush.refused');
    }
  }

  /** Polls that failed since the last success; drives `notificationPollDelay`. */
  private consecutiveFailures = 0;

  ngOnInit(): void {
    // J11-T1: a change to the inbox arrives on the live channel and refreshes
    // the bell at once; the poll below stays as the fallback.
    this.live.connect();
    this.live.notifications.pipe(
      switchMap(() => this.pollOnce()),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe();
    pageVisible$(this.document).pipe(
      // `switchMap`: going hidden unsubscribes the running loop, which also
      // aborts an in-flight request; going visible starts a fresh loop whose
      // first poll is immediate.
      switchMap(visible => visible ? this.pollLoop() : EMPTY),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe();
  }

  /**
   * Poll once, then keep re-polling after a delay chosen at each completion —
   * so a failure lengthens the *next* gap and a success shortens it back.
   */
  private pollLoop(): Observable<void> {
    return this.pollOnce().pipe(
      repeat({ delay: () => timer(notificationPollDelay(this.consecutiveFailures)) }),
    );
  }

  /** One poll that always completes, recording success or failure for the backoff. */
  private pollOnce(): Observable<void> {
    return this.api.post<{ notifications: XrmNotif[]; unread_count: number }>(
      '/api/v1/notification/poll', {}
    ).pipe(
      tap(res => {
        this.notifications.set(res.notifications ?? []);
        this.unreadCount.set(res.unread_count ?? 0);
        this.consecutiveFailures = 0;
      }),
      map(() => undefined),
      // A failed poll is not user-actionable (the bell simply keeps showing
      // what it last knew), so it is absorbed here — it must not error the
      // loop out, only push the next attempt further away.
      catchError(() => {
        this.consecutiveFailures += 1;
        return of(undefined);
      }),
    );
  }

  toggle(): void { this.isOpen.update(v => !v); }

  onDocumentClick(e: MouseEvent): void {
    if (this.isOpen() && !this.host.nativeElement.contains(e.target)) {
      this.isOpen.set(false);
    }
  }

  onNotifClick(n: XrmNotif): void {
    if (!n.isRead) {
      this.notifications.update(list => list.map(x => x.id === n.id ? { ...x, isRead: true } : x));
      this.unreadCount.update(c => Math.max(0, c - 1));
      this.api.post('/api/v1/notification/read', { id: n.id }).subscribe();
    }
    if (n.route) { this.router.navigateByUrl(n.route); this.isOpen.set(false); }
  }

  onNotifKeydown(event: KeyboardEvent, notification: XrmNotif): void {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    this.onNotifClick(notification);
  }

  /** J11-T2: opening a group reads every notification in it and follows its link. */
  onGroupClick(group: NotifGroup): void {
    this.readGroup(group);
    if (group.latest.route) { this.router.navigateByUrl(group.latest.route); this.isOpen.set(false); }
  }

  onGroupKeydown(event: KeyboardEvent, group: NotifGroup): void {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    this.onGroupClick(group);
  }

  markGroupRead(group: NotifGroup, event: Event): void {
    event.stopPropagation();
    this.readGroup(group);
  }

  private readGroup(group: NotifGroup): void {
    const unread = group.items.filter(n => !n.isRead).map(n => n.id);
    if (unread.length === 0) return;
    const ids = new Set(unread);
    this.notifications.update(list => list.map(n => ids.has(n.id) ? { ...n, isRead: true } : n));
    this.unreadCount.update(c => Math.max(0, c - unread.length));
    for (const id of unread) this.api.post('/api/v1/notification/read', { id }).subscribe();
  }

  markRead(id: string, event: Event): void {
    event.stopPropagation();
    this.notifications.update(list => list.map(n => n.id === id ? { ...n, isRead: true } : n));
    this.unreadCount.update(c => Math.max(0, c - 1));
    this.api.post('/api/v1/notification/read', { id }).subscribe();
  }

  clearAll(): void {
    this.notifications.update(list => list.map(n => ({ ...n, isRead: true })));
    this.unreadCount.set(0);
    this.api.post('/api/v1/notification/clear', {}).subscribe();
  }

  notifIcon(type: number): string {
    switch (type) {
      case 1:  return 'las la-check-circle';
      case 2:  return 'las la-exclamation-triangle';
      case 3:  return 'las la-times-circle';
      default: return 'las la-info-circle';
    }
  }

  notifIconColor(type: number): string {
    switch (type) {
      case 1:  return '#22c55e';
      case 2:  return '#f59e0b';
      case 3:  return '#ef4444';
      default: return 'var(--color-accent)';
    }
  }

  notifIconBg(type: number): string {
    switch (type) {
      case 1:  return 'rgba(34,197,94,.12)';
      case 2:  return 'rgba(245,158,11,.12)';
      case 3:  return 'rgba(239,68,68,.12)';
      default: return 'color-mix(in srgb, var(--color-accent) 12%, transparent)';
    }
  }

  formatTime(epoch: number): string {
    const mins = Math.floor((Date.now() - epoch * 1000) / 60_000);
    if (mins < 1)    return 'Just now';
    if (mins < 60)   return `${mins}m ago`;
    if (mins < 1440) return `${Math.floor(mins / 60)}h ago`;
    return new Date(epoch * 1000).toLocaleDateString();
  }
}
