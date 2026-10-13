import {
  ChangeDetectionStrategy, Component, DestroyRef, effect, inject, input, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LocalDatePipe, TranslatePipe } from '@attome/base';
import {
  RecordTimelineService, TIMELINE_KINDS, TimelineEntry, TimelineEntryKind,
} from './record-timeline.service';

const KIND_ICONS: Record<TimelineEntryKind, string> = {
  audit_event:      'las la-pen',
  state_transition: 'las la-sync',
  communication:    'las la-envelope',
  note:             'las la-sticky-note',
  activity:         'las la-tasks',
  decision:         'las la-gavel',
};

/** Entries fetched per page. */
export const TIMELINE_PAGE_SIZE = 25;

/**
 * U3 (basic-units plan, D-601) — a record's timeline: its audit events, state
 * transitions, communications, notes, activities and linked decisions, newest
 * first, over `GET /api/v1/{entity}/{id}/timeline`. The server decides every
 * entry (record access, each source row's own security, field security); this
 * panel only renders what it is given.
 *
 * The kind chips filter server-side: toggling one refetches from the first
 * page, because a cursor from a differently-filtered feed would skip entries.
 * "Load more" appends the next keyset page.
 */
@Component({
  selector: 'xrm-record-timeline-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe],
  styleUrls: ['./record-timeline-panel.component.css'],
  templateUrl: './record-timeline-panel.component.html',
})
export class RecordTimelinePanelComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input.required<string>();

  private readonly service    = inject(RecordTimelineService);
  private readonly destroyRef = inject(DestroyRef);

  readonly kinds = TIMELINE_KINDS;
  /** Kinds switched on; empty = all. */
  readonly selected   = signal<ReadonlySet<TimelineEntryKind>>(new Set());
  readonly entries    = signal<TimelineEntry[]>([]);
  readonly nextCursor = signal<string | null>(null);
  readonly loading    = signal(false);
  readonly error      = signal(false);

  /** Bumped on every fresh load so a slow earlier page cannot land late. */
  private generation = 0;

  constructor() {
    effect(() => {
      const entity = this.entityName();
      const id = this.recordId();
      untracked(() => {
        if (entity && id) this.reload();
      });
    });
  }

  icon(kind: TimelineEntryKind): string {
    return KIND_ICONS[kind] ?? 'las la-circle';
  }

  isSelected(kind: TimelineEntryKind): boolean {
    return this.selected().has(kind);
  }

  toggle(kind: TimelineEntryKind): void {
    const next = new Set(this.selected());
    if (next.has(kind)) next.delete(kind); else next.add(kind);
    this.selected.set(next);
    this.reload();
  }

  clearFilter(): void {
    if (this.selected().size === 0) return;
    this.selected.set(new Set());
    this.reload();
  }

  reload(): void {
    this.entries.set([]);
    this.nextCursor.set(null);
    this.fetch(null, ++this.generation);
  }

  loadMore(): void {
    const cursor = this.nextCursor();
    if (cursor && !this.loading()) this.fetch(cursor, this.generation);
  }

  private fetch(cursor: string | null, generation: number): void {
    this.loading.set(true);
    this.error.set(false);
    this.service.timeline(this.entityName(), this.recordId(), {
      cursor,
      pageSize: TIMELINE_PAGE_SIZE,
      kinds: [...this.selected()],
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: page => {
        if (generation !== this.generation) return;
        this.entries.update(list => [...list, ...page.items]);
        this.nextCursor.set(page.next_cursor ?? null);
        this.loading.set(false);
      },
      error: () => {
        if (generation !== this.generation) return;
        this.loading.set(false);
        this.error.set(true);
      },
    });
  }
}
