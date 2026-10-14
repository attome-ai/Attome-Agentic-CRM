import { DestroyRef, Injectable, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NavigationEnd, Router } from '@angular/router';
import { ApiService } from '@attome/base';
import { Observable, filter } from 'rxjs';

/** One kept item: a record, a view or a page (B9-T2). */
export interface FavouriteItem {
  id: string;
  kind: 'record' | 'view' | 'page';
  entity: string | null;
  ref: string;
  label: string | null;
  pinned: boolean;
  /** A record deleted since it was kept. */
  deleted: boolean;
}

/** A person's own list (`team_id` null) or a team's. */
export interface FavouriteList {
  id: string;
  name: string;
  team_id: string | null;
  items: FavouriteItem[];
}

/** A record the person opened lately. */
export interface RecentItem {
  entity: string;
  record_id: string;
  label: string | null;
  opened_at: string;
  deleted: boolean;
}

/** An item as saved: what the list endpoints take. */
export interface FavouriteItemInput {
  kind: FavouriteItem['kind'];
  entity: string | null;
  ref: string;
  label: string | null;
  pinned: boolean;
}

interface Page<T> { items: T[] }

/** How long opens wait to go out together. */
export const RECENT_FLUSH_MS = 5_000;
/** The most opens the API takes at once. */
export const RECENT_BATCH = 50;
/** Pinned items a list may hold: the Ctrl+1..9 shortcuts. */
export const MAX_PINNED = 9;
/** The name of the list a starred record goes to when the person has none. */
export const DEFAULT_LIST_NAME = 'Favourites';

const RECORD_URL = /^\/xrm\/entity\/([a-z][a-z0-9_]{0,62})\/form\?(?:.*&)?id=([0-9a-f-]{36})(?:&|$)/i;

/** The record a record-form URL opens, or null for any other page. */
export function recordFromUrl(url: string): { entity: string; record_id: string } | null {
  const match = RECORD_URL.exec(url);
  return match ? { entity: match[1], record_id: match[2].toLowerCase() } : null;
}

/** An item back in the shape the list endpoints take. */
export function toInput(item: FavouriteItem): FavouriteItemInput {
  return { kind: item.kind, entity: item.entity, ref: item.ref, label: item.label, pinned: item.pinned };
}

/** `items` with the one at `from` moved to `to`. */
export function moved<T>(items: readonly T[], from: number, to: number): T[] {
  const out = [...items];
  if (from < 0 || from >= out.length || to < 0 || to >= out.length) return out;
  const [item] = out.splice(from, 1);
  out.splice(to, 0, item);
  return out;
}

/**
 * Recent records and favourites for the signed-in person (B9-T3): the lists,
 * the opens reported in batches, the pinned items behind Ctrl+1..9, and
 * opening any of them. Every change saves the whole list, as the API takes it.
 */
@Injectable({ providedIn: 'root' })
export class FavouritesService {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  readonly lists = signal<FavouriteList[]>([]);
  readonly recent = signal<RecentItem[]>([]);

  /** Pinned items, own lists first, in list order; the first nine. */
  readonly pinned = computed(() =>
    this.lists()
      .flatMap(list => list.items.filter(item => item.pinned && !item.deleted))
      .slice(0, MAX_PINNED));

  private pending: { entity: string; record_id: string }[] = [];
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private tracking = false;

  /** Loads the lists and recents, and starts noting record opens. */
  start(): void {
    this.reload();
    if (this.tracking) return;
    this.tracking = true;
    this.router.events
      .pipe(filter(e => e instanceof NavigationEnd), takeUntilDestroyed(this.destroyRef))
      .subscribe(e => {
        const opened = recordFromUrl((e as NavigationEnd).urlAfterRedirects);
        if (opened) this.noteOpen(opened.entity, opened.record_id);
      });
  }

  reload(): void {
    this.api.get<Page<FavouriteList>>('/api/v1/me/favourites').subscribe({
      next: page => this.lists.set(page.items),
      error: () => this.lists.set([]),
    });
    this.loadRecent();
  }

  private loadRecent(): void {
    this.api.get<Page<RecentItem>>('/api/v1/me/recent', { limit: '20' }).subscribe({
      next: page => this.recent.set(page.items),
      error: () => this.recent.set([]),
    });
  }

  /** Notes one open; they go out together a few seconds later. */
  noteOpen(entity: string, recordId: string): void {
    this.pending = this.pending.filter(o => !(o.entity === entity && o.record_id === recordId));
    this.pending.push({ entity, record_id: recordId });
    if (this.pending.length >= RECENT_BATCH) {
      this.flush();
      return;
    }
    this.flushTimer ??= setTimeout(() => this.flush(), RECENT_FLUSH_MS);
  }

  /** Sends the noted opens now. */
  flush(): void {
    if (this.flushTimer) {
      clearTimeout(this.flushTimer);
      this.flushTimer = null;
    }
    const items = this.pending.slice(-RECENT_BATCH);
    this.pending = [];
    if (!items.length) return;
    this.api.post<void>('/api/v1/me/recent', { items }).subscribe({
      next: () => this.loadRecent(),
      error: () => undefined,
    });
  }

  clearRecent(): void {
    this.pending = [];
    this.api.delete('/api/v1/me/recent').subscribe({ next: () => this.recent.set([]), error: () => undefined });
  }

  /** The first own list holding this record, if any. */
  listWithRecord(entity: string, recordId: string): FavouriteList | null {
    return this.lists().find(l => !l.team_id
      && l.items.some(i => i.kind === 'record' && i.entity === entity && i.ref === recordId)) ?? null;
  }

  /** Stars or unstars a record in the person's first own list. */
  toggleRecord(entity: string, recordId: string, label: string | null): void {
    const holding = this.listWithRecord(entity, recordId);
    if (holding) {
      this.save(holding, holding.items
        .filter(i => !(i.kind === 'record' && i.entity === entity && i.ref === recordId))
        .map(toInput));
      return;
    }
    this.add({ kind: 'record', entity, ref: recordId, label, pinned: false });
  }

  /** Adds an item to the person's first own list, creating it when there is none. */
  add(item: FavouriteItemInput): void {
    const own = this.lists().find(l => !l.team_id);
    if (!own) {
      this.api.post<FavouriteList>('/api/v1/me/favourites/lists', { name: DEFAULT_LIST_NAME, items: [item] })
        .subscribe({ next: () => this.reload(), error: () => undefined });
      return;
    }
    this.save(own, [...own.items.map(toInput), item]);
  }

  move(list: FavouriteList, from: number, to: number): void {
    this.save(list, moved(list.items, from, to).map(toInput));
  }

  togglePin(list: FavouriteList, item: FavouriteItem): void {
    this.save(list, list.items.map(i => (i.id === item.id ? { ...toInput(i), pinned: !i.pinned } : toInput(i))));
  }

  remove(list: FavouriteList, item: FavouriteItem): void {
    this.save(list, list.items.filter(i => i.id !== item.id).map(toInput));
  }

  /** Saves `list` with `items`, in order; the lists reload either way. */
  save(list: FavouriteList, items: FavouriteItemInput[]): void {
    const path = list.team_id
      ? `/api/v1/teams/${list.team_id}/favourites/lists/${list.id}`
      : `/api/v1/me/favourites/lists/${list.id}`;
    const request: Observable<FavouriteList> = this.api.put<FavouriteList>(path, { name: list.name, items });
    request.subscribe({ next: () => this.reload(), error: () => this.reload() });
  }

  /** Opens a kept item: a record's form, a view's list, or a page. */
  open(item: Pick<FavouriteItem, 'kind' | 'entity' | 'ref'>): void {
    if (item.kind === 'record' && item.entity) {
      void this.router.navigate(['/xrm', 'entity', item.entity, 'form'], { queryParams: { id: item.ref } });
    } else if (item.kind === 'view' && item.entity) {
      void this.router.navigate(['/xrm', 'entity', item.entity, 'list'], { queryParams: { view: item.ref } });
    } else if (item.kind === 'page') {
      void this.router.navigateByUrl(item.ref);
    }
  }

  /** Ctrl+N: opens the Nth pinned item (1-based); false when there is none. */
  openPinned(n: number): boolean {
    const item = this.pinned()[n - 1];
    if (!item) return false;
    this.open(item);
    return true;
  }
}
