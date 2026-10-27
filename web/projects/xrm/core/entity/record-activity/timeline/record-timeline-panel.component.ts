import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, output, signal, untracked,
} from '@angular/core';
import { DOCUMENT } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Observable } from 'rxjs';
import { LiveChannel, LocalDatePipe, TranslatePipe } from '@attome/base';
import {
  InlineActivity, RecordTimelineService, TIMELINE_KINDS, TimelineEntry, TimelineEntryKind, TimelineSummary,
  isPinned,
} from './record-timeline.service';

// Keyed by string so the B1-T1 kinds render before and after the API types
// list them.
const KIND_ICONS: Record<string, string> = {
  audit_event:      'las la-pen',
  state_transition: 'las la-sync',
  communication:    'las la-envelope',
  note:             'las la-sticky-note',
  activity:         'las la-tasks',
  decision:         'las la-gavel',
  approval:         'las la-check-circle',
  flow_run:         'las la-project-diagram',
  agent_run:        'las la-robot',
  web_visit:        'las la-globe',
};

/** Entries fetched per page. */
export const TIMELINE_PAGE_SIZE = 25;

/** B1-T2: the kinds that count as contact with the record's people. */
const CONTACT_KINDS: ReadonlySet<string> = new Set(['communication', 'activity']);

/** B1-T2: the child entities whose new rows may be this record's. */
const CHILD_ENTITIES = ['note', 'activity', 'communication'];

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * B1-T2: where "no contact for N days" markers go: before the entry at each
 * index whose previous (newer) contact entry is at least `gapDays` days after
 * it, with the gap in whole days. Pure.
 */
export function contactGaps(entries: readonly TimelineEntry[], gapDays: number): Map<number, number> {
  const gaps = new Map<number, number>();
  if (gapDays <= 0) return gaps;
  let newer: number | null = null;
  entries.forEach((entry, index) => {
    if (!CONTACT_KINDS.has(entry.kind)) return;
    const at = Date.parse(entry.occurred_at);
    if (Number.isNaN(at)) return;
    if (newer !== null) {
      const days = Math.floor((newer - at) / DAY_MS);
      if (days >= gapDays) gaps.set(index, days);
    }
    newer = at;
  });
  return gaps;
}

/** The inline form open, if any. */
export type InlineForm = 'note' | 'call' | 'task' | null;

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
 *
 * B1-T3: on open, the AI summary of the timeline sits above the chips,
 * citing the events it draws on; a citation scrolls to its entry. When AI is
 * off, unlicensed or refused, or there is nothing to summarise, the panel
 * shows no summary rather than an error.
 *
 * B1-T2: pinned entries sit on top (read through the timeline itself, so
 * only what the person may see); each entry can be pinned or unpinned by a
 * person who may update the record. A "no contact for N days" marker shows
 * where calls, emails and other activities stop for `gapDays` or more. A
 * note, a logged call or a task is added inline, and a communication offers
 * Reply (the `reply` output, for the host's composer). The live channel
 * counts changes to the record and its notes, activities and communications
 * while the panel is open; "N new" reloads.
 */
@Component({
  selector: 'xrm-record-timeline-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, LocalDatePipe],
  styleUrls: ['./record-timeline-panel.component.css'],
  templateUrl: './record-timeline-panel.component.html',
})
export class RecordTimelinePanelComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input.required<string>();
  /** B1-T2: the gap, in days, a "no contact" marker shows from; 0 shows none. */
  readonly gapDays    = input(14);
  /** B1-T2: Reply on a communication, for the host to open its composer. */
  readonly reply      = output<TimelineEntry>();

  private readonly service    = inject(RecordTimelineService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly live       = inject(LiveChannel);

  readonly kinds = TIMELINE_KINDS;
  /** Kinds switched on; empty = all. */
  readonly selected   = signal<ReadonlySet<TimelineEntryKind>>(new Set());
  readonly entries    = signal<TimelineEntry[]>([]);
  readonly nextCursor = signal<string | null>(null);
  readonly loading    = signal(false);
  readonly error      = signal(false);
  readonly summary        = signal<TimelineSummary | null>(null);
  readonly summaryLoading = signal(false);
  /** The entry a citation pointed at. */
  readonly highlighted    = signal<string | null>(null);
  /** B1-T2: the pinned entries, newest first. */
  readonly pinnedEntries  = signal<TimelineEntry[]>([]);
  /** B1-T2: an entry whose pin is being changed. */
  readonly pinning        = signal<string | null>(null);
  readonly actionError    = signal(false);
  /** B1-T2: the inline form open, and its text and due date. */
  readonly form           = signal<InlineForm>(null);
  readonly formText       = signal('');
  readonly formDue        = signal('');
  readonly saving         = signal(false);
  /** B1-T2: changes the live channel reported since the last load. */
  readonly fresh          = signal(0);

  readonly gaps = computed(() => contactGaps(this.entries(), this.gapDays()));

  private readonly document = inject(DOCUMENT);
  private summaryGeneration = 0;
  private unwatch: (() => void)[] = [];

  /** Bumped on every fresh load so a slow earlier page cannot land late. */
  private generation = 0;

  constructor() {
    effect(() => {
      const entity = this.entityName();
      const id = this.recordId();
      untracked(() => {
        if (entity && id) {
          this.reload();
          this.loadSummary();
          this.loadPinned();
          this.watch(entity);
        }
      });
    });
    this.live.records.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(frame => {
      if ('overflow' in frame) {
        this.fresh.update(n => n + 1);
        return;
      }
      const mine = frame.changes.filter(c =>
        (c.entity === this.entityName() && c.id === this.recordId())
        || (CHILD_ENTITIES.includes(c.entity) && c.op === 'create'));
      if (mine.length) this.fresh.update(n => n + mine.length);
    });
    this.destroyRef.onDestroy(() => this.stopWatching());
  }

  /** Scrolls to the entry a summary citation names. */
  showEntry(sourceId: string): void {
    this.highlighted.set(sourceId);
    this.document.getElementById('tl-' + sourceId)?.scrollIntoView?.({ block: 'center' });
  }

  private loadSummary(): void {
    const generation = ++this.summaryGeneration;
    this.summary.set(null);
    this.summaryLoading.set(true);
    this.service.summary(this.entityName(), this.recordId())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: summary => {
          if (generation !== this.summaryGeneration) return;
          this.summary.set(summary);
          this.summaryLoading.set(false);
        },
        error: () => {
          if (generation !== this.summaryGeneration) return;
          this.summaryLoading.set(false);
        },
      });
  }

  icon(kind: TimelineEntryKind): string {
    return KIND_ICONS[kind] ?? 'las la-circle';
  }

  pinned(entry: TimelineEntry): boolean {
    return isPinned(entry);
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
    this.fresh.set(0);
    this.entries.set([]);
    this.nextCursor.set(null);
    this.fetch(null, ++this.generation);
  }

  /** "N new": shows the changes the live channel reported. */
  showFresh(): void {
    this.reload();
    this.loadPinned();
  }

  loadMore(): void {
    const cursor = this.nextCursor();
    if (cursor && !this.loading()) this.fetch(cursor, this.generation);
  }

  /** Pins an entry, or unpins a pinned one. */
  togglePin(entry: TimelineEntry): void {
    const key = entry.kind + ':' + entry.source_id;
    this.pinning.set(key);
    this.actionError.set(false);
    const call = isPinned(entry)
      ? this.service.unpin(this.entityName(), this.recordId(), entry)
      : this.service.pin(this.entityName(), this.recordId(), entry);
    call.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        const now = !isPinned(entry);
        const flip = (e: TimelineEntry) =>
          e.kind === entry.kind && e.source_id === entry.source_id ? { ...e, pinned: now } : e;
        this.entries.update(list => list.map(flip));
        this.pinning.set(null);
        this.loadPinned();
      },
      error: () => {
        this.pinning.set(null);
        this.actionError.set(true);
      },
    });
  }

  openForm(form: InlineForm): void {
    this.form.set(this.form() === form ? null : form);
    this.formText.set('');
    this.formDue.set('');
    this.actionError.set(false);
  }

  /** Saves the open inline form, then shows the new entry. */
  saveForm(): void {
    const form = this.form();
    const text = this.formText().trim();
    if (!form || !text || this.saving()) return;
    const call: Observable<unknown> = form === 'note'
      ? this.service.addNote(this.entityName(), this.recordId(), text)
      : this.service.logActivity(this.entityName(), this.recordId(), {
        type: form, subject: text, due: form === 'task' ? this.formDue() || null : null,
      } satisfies InlineActivity);
    this.saving.set(true);
    this.actionError.set(false);
    call.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.saving.set(false);
        this.form.set(null);
        this.reload();
      },
      error: () => {
        this.saving.set(false);
        this.actionError.set(true);
      },
    });
  }

  private loadPinned(): void {
    this.service.pinned(this.entityName(), this.recordId())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: page => this.pinnedEntries.set(page.items),
        // Pins are extra: without them the timeline still shows.
        error: () => this.pinnedEntries.set([]),
      });
  }

  private watch(entity: string): void {
    this.stopWatching();
    this.unwatch = [entity, ...CHILD_ENTITIES].map(e => this.live.watch(e));
  }

  private stopWatching(): void {
    for (const stop of this.unwatch) stop();
    this.unwatch = [];
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
