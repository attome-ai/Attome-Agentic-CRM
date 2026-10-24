import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { ApiError, ApiService, LangService, Page, TranslatePipe } from '@attome/base';
import { QueryService } from '@attome/xrm/core/query/data';
import { catchError, forkJoin, of } from 'rxjs';

import { EntityService } from '@attome/xrm/core/entity';

const DAY_MS = 24 * 3600 * 1000;

/** The weeks the board shows by default. */
export const BOOKING_WEEKS = 8;

/** The share a click books a person at. */
export const DEFAULT_ALLOCATION_PERCENT = 50;

/** One person's row: the capacity route's figures (M72). */
export interface BookingPerson {
  resource_id: string;
  resource_name?: string | null;
  capacity_hours: number;
  allocated_hours: number;
  utilization_pct: number;
  over_allocated: boolean;
}

/** A booking: one `resource_allocation` row. */
export interface Booking {
  id: string;
  userId: string;
  regardingEntity: string | null;
  regardingId: string | null;
  percent: number;
  start: string;
  end: string | null;
  rowVersion: number;
}

/** A leave period: one `resource_availability` row. */
export interface Leave {
  userId: string;
  start: string;
  end: string;
}

/** The Monday on or before `date` (`YYYY-MM-DD`, UTC). Pure. */
export function weekStart(date: string): string {
  const d = new Date(`${date}T00:00:00Z`);
  const back = (d.getUTCDay() + 6) % 7;
  return new Date(d.getTime() - back * DAY_MS).toISOString().slice(0, 10);
}

/** `date` plus `days`. Pure. */
export function addDays(date: string, days: number): string {
  return new Date(Date.parse(`${date}T00:00:00Z`) + days * DAY_MS).toISOString().slice(0, 10);
}

/**
 * Where a date range sits on the board from `from` over `days` days, as
 * percentages of its width; an open end runs to the board's end. Pure.
 */
export function spanGeometry(start: string, end: string | null, from: string, days: number): { offset: number; width: number } | null {
  const a = Date.parse(`${start.slice(0, 10)}T00:00:00Z`);
  const b = end ? Date.parse(`${end.slice(0, 10)}T00:00:00Z`) + DAY_MS : Number.POSITIVE_INFINITY;
  const lo = Date.parse(`${from}T00:00:00Z`);
  const hi = lo + days * DAY_MS;
  if (Number.isNaN(a) || b <= lo || a >= hi) return null;
  const left = (Math.max(a, lo) - lo) / (hi - lo);
  const right = (Math.min(b, hi) - lo) / (hi - lo);
  return { offset: left * 100, width: Math.max(1, (right - left) * 100) };
}

/**
 * V4-T1 — the project booking board, the timeline's resource mode for
 * projects (shared with I3's dispatch board): one row per person, from the
 * capacity route (M72: capacity net of leave, what is allocated, over
 * allocation), their bookings (`resource_allocation`) as bars over the
 * weeks shown, and their leave (`resource_availability`) shaded behind.
 * Dragging a booking to another person moves it, written with its row
 * version (`If-Match`) so a stale board is told to reload. Opened for a
 * project (`projectId`), a click on a week of a person's row books them on
 * that project for that week. The week axis runs in the reading direction,
 * so it mirrors in Arabic.
 */
@Component({
  selector: 'xrm-booking-board',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="bb" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="booking-board">
      <header class="bb-head">
        <h2>{{ 'bookingBoard.title' | translate }} <span dir="ltr">{{ from() }} – {{ to() }}</span></h2>
        <div class="bb-nav">
          <button type="button" data-testid="bb-prev" (click)="shift(-1)">{{ 'bookingBoard.earlier' | translate }}</button>
          <button type="button" data-testid="bb-next" (click)="shift(1)">{{ 'bookingBoard.later' | translate }}</button>
        </div>
      </header>
      @if (projectId()) {
        <p class="bb-hint">{{ 'bookingBoard.clickToBook' | translate: { percent: percent } }}</p>
      }
      @if (message(); as m) { <p class="bb-message" role="alert" data-testid="bb-message">{{ m }}</p> }
      <div class="bb-grid" role="grid" [attr.aria-label]="'bookingBoard.grid' | translate">
        <div class="bb-row bb-axis" role="row">
          <div class="bb-name" role="columnheader">{{ 'bookingBoard.person' | translate }}</div>
          <div class="bb-weeks" role="columnheader">
            @for (w of weekStarts(); track w) { <span dir="ltr">{{ w.slice(5) }}</span> }
          </div>
        </div>
        @for (p of people(); track p.resource_id) {
          <div class="bb-row" role="row" data-testid="bb-row" [attr.data-user]="p.resource_id"
               [class.bb-over]="p.over_allocated"
               (dragover)="$event.preventDefault()" (drop)="drop($event, p)">
            <div class="bb-name" role="rowheader">
              <span>{{ p.resource_name || p.resource_id }}</span>
              <span class="bb-load" data-testid="bb-load">{{ 'bookingBoard.load' | translate: { pct: round(p.utilization_pct) } }}</span>
              @if (p.over_allocated) {
                <span class="bb-flag" data-testid="bb-over">{{ 'bookingBoard.over' | translate }}</span>
              }
            </div>
            <div class="bb-track" role="gridcell">
              @for (l of leaveOf(p.resource_id); track $index) {
                @if (geometry(l.start, l.end); as g) {
                  <div class="bb-leave" data-testid="bb-leave" [attr.title]="'bookingBoard.leave' | translate"
                       [style.inset-inline-start.%]="g.offset" [style.inline-size.%]="g.width"></div>
                }
              }
              @if (projectId()) {
                <div class="bb-cells">
                  @for (w of weekStarts(); track w) {
                    <button type="button" class="bb-cell" data-testid="bb-cell" [attr.data-week]="w"
                            [attr.aria-label]="'bookingBoard.book' | translate: { name: p.resource_name || p.resource_id, week: w }"
                            [disabled]="busy()" (click)="book(p, w)"></button>
                  }
                </div>
              }
              @for (b of bookingsOf(p.resource_id); track b.id) {
                @if (geometry(b.start, b.end); as g) {
                  <div class="bb-bar" draggable="true" data-testid="bb-bar" [attr.data-booking]="b.id"
                       [class.bb-bar--this]="b.regardingId === projectId()"
                       [style.inset-inline-start.%]="g.offset" [style.inline-size.%]="g.width"
                       (dragstart)="dragStart(b)">{{ label(b) }}</div>
                }
              }
            </div>
          </div>
        } @empty {
          <p class="bb-muted">{{ 'bookingBoard.noPeople' | translate }}</p>
        }
      </div>
    </section>
  `,
  styles: [`
    .bb { display: grid; gap: .75rem; }
    .bb-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: .5rem; }
    .bb-head h2 { margin: 0; }
    .bb-nav { display: flex; gap: .5rem; }
    .bb-hint { margin: 0; color: var(--color-text-secondary, #666); font-size: .8125rem; }
    .bb-grid { overflow-x: auto; border: 1px solid var(--color-border, #ddd); border-radius: 8px; }
    .bb-row { display: grid; grid-template-columns: 12rem minmax(40rem, 1fr); border-block-end: 1px solid var(--color-border, #eee); min-block-size: 2.75rem; }
    .bb-name { padding: .375rem .5rem; display: flex; flex-direction: column; gap: .125rem; border-inline-end: 1px solid var(--color-border, #eee); }
    .bb-load { font-size: .75rem; color: var(--color-text-secondary, #666); }
    .bb-flag { font-size: .75rem; color: var(--color-danger, #c53030); font-weight: 600; }
    .bb-over .bb-name { background: var(--color-danger-bg, #fdecec); }
    .bb-weeks { display: grid; grid-auto-flow: column; grid-auto-columns: 1fr; font-size: .7rem; color: var(--color-text-secondary, #666); padding-block: .25rem; }
    .bb-track { position: relative; }
    .bb-cells { position: absolute; inset: 0; display: grid; grid-auto-flow: column; grid-auto-columns: 1fr; }
    .bb-cell { border: none; border-inline-end: 1px dashed var(--color-border, #eee); background: transparent; cursor: copy; }
    .bb-cell:hover, .bb-cell:focus-visible { background: var(--color-bg-alt, #f7f7f7); }
    .bb-leave { position: absolute; inset-block: 0; background: var(--color-warning-bg, #fff4e0); opacity: .8; pointer-events: none; }
    .bb-bar { position: absolute; inset-block: .4rem; overflow: hidden; white-space: nowrap; text-overflow: ellipsis;
              padding-inline: .375rem; font-size: .75rem; border-radius: 4px; cursor: grab;
              background: var(--color-bg-alt, #f1f1f1); border: 1px solid var(--color-border, #bbb); }
    .bb-bar--this { background: var(--color-primary-bg, #e3edf9); border-color: var(--color-primary, #2b6cb0); }
    .bb-message { color: var(--color-danger, #c53030); margin: 0; }
    .bb-muted { color: var(--color-text-secondary, #666); padding: .5rem; }
  `],
})
export class BookingBoardComponent {
  private readonly api = inject(ApiService);
  private readonly query = inject(QueryService);
  private readonly entities = inject(EntityService);
  protected readonly lang = inject(LangService);

  /** The first day shown (`YYYY-MM-DD`); this week's Monday when unset. */
  readonly start = input<string | undefined>(undefined);
  readonly weeks = input(BOOKING_WEEKS);
  /** The project a click books people on; read only without one. */
  readonly projectId = input<string | null>(null);
  /** The project's entity, as `resource_allocation.regarding_entity` names it. */
  readonly projectEntity = input('project');

  readonly percent = DEFAULT_ALLOCATION_PERCENT;
  readonly people = signal<BookingPerson[]>([]);
  readonly bookings = signal<Booking[]>([]);
  readonly leave = signal<Leave[]>([]);
  readonly message = signal<string | null>(null);
  readonly busy = signal(false);
  /** Weeks moved from the start by Earlier and Later. */
  private readonly offsetWeeks = signal(0);
  private dragged: Booking | null = null;

  readonly from = computed(() =>
    addDays(weekStart(this.start() ?? new Date().toISOString().slice(0, 10)), this.offsetWeeks() * 7));
  readonly days = computed(() => this.weeks() * 7);
  readonly to = computed(() => addDays(this.from(), this.days() - 1));
  readonly weekStarts = computed(() => Array.from({ length: this.weeks() }, (_, i) => addDays(this.from(), i * 7)));

  constructor() {
    effect(() => {
      const from = this.from();
      const to = this.to();
      untracked(() => this.load(from, to));
    });
  }

  round(n: number): number {
    return Math.round(n);
  }

  shift(weeks: number): void {
    this.offsetWeeks.update(w => w + weeks);
  }

  bookingsOf(userId: string): Booking[] {
    return this.bookings().filter(b => b.userId === userId);
  }

  leaveOf(userId: string): Leave[] {
    return this.leave().filter(l => l.userId === userId);
  }

  geometry(start: string, end: string | null) {
    return spanGeometry(start, end, this.from(), this.days());
  }

  label(b: Booking): string {
    return this.lang.translate('bookingBoard.bar', { percent: b.percent, project: b.regardingId ?? '' });
  }

  dragStart(b: Booking): void {
    this.dragged = b;
  }

  /** Moves the dragged booking to `person`. */
  drop(event: Event, person: BookingPerson): void {
    event.preventDefault();
    const b = this.dragged;
    this.dragged = null;
    if (!b || b.userId === person.resource_id) return;
    this.busy.set(true);
    this.message.set(null);
    this.entities.update('resource_allocation', b.id, { user_id: person.resource_id }, b.rowVersion).subscribe({
      next: saved => {
        this.busy.set(false);
        const rv = Number((saved as unknown as { row_version?: number }).row_version ?? b.rowVersion + 1);
        this.bookings.update(list => list.map(x => (x.id === b.id ? { ...x, userId: person.resource_id, rowVersion: rv } : x)));
        this.refreshCapacity();
      },
      error: (e: ApiError) => this.failed(e),
    });
  }

  /** Books `person` on the board's project for the week from `week`. */
  book(person: BookingPerson, week: string): void {
    const project = this.projectId();
    if (!project) return;
    this.busy.set(true);
    this.message.set(null);
    const body = {
      user_id: person.resource_id,
      regarding_entity: this.projectEntity(),
      regarding_id: project,
      allocation_percent: this.percent,
      start_date: week,
      end_date: addDays(week, 6),
    };
    this.entities.create('resource_allocation', body).subscribe({
      next: saved => {
        this.busy.set(false);
        const rec = saved as unknown as { id: string; row_version?: number };
        this.bookings.update(list => [...list, {
          id: rec.id, userId: person.resource_id, regardingEntity: body.regarding_entity, regardingId: project,
          percent: this.percent, start: week, end: body.end_date, rowVersion: Number(rec.row_version ?? 0),
        }]);
        this.refreshCapacity();
      },
      error: (e: ApiError) => this.failed(e),
    });
  }

  private failed(e: ApiError): void {
    this.busy.set(false);
    this.message.set(e.status === 409 ? this.lang.translate('bookingBoard.stale') : this.lang.errorText(e));
    if (e.status === 409) this.load(this.from(), this.to());
  }

  private capacity(from: string, to: string) {
    return this.api.get<Page<BookingPerson>>('/api/v1/resources/capacity', {
      from, to, page: '1', page_size: '100',
    });
  }

  private refreshCapacity(): void {
    this.capacity(this.from(), this.to()).pipe(catchError(() => of(null))).subscribe(page => {
      if (page) this.people.set(page.items);
    });
  }

  private load(from: string, to: string): void {
    forkJoin({
      people: this.capacity(from, to),
      bookings: this.query.execute({
        entity: 'resource_allocation', page: 1, page_size: 500,
        filters: [{ field: 'start_date', op: 'lte', value: to }],
      }),
      leave: this.query.execute({
        entity: 'resource_availability', page: 1, page_size: 500,
        filters: [{ field: 'leave_start', op: 'lte', value: to }, { field: 'leave_end', op: 'gte', value: from }],
      }),
    }).pipe(catchError((e: ApiError) => { this.message.set(this.lang.errorText(e)); return of(null); })).subscribe(res => {
      if (!res) return;
      this.people.set(res.people.items);
      this.bookings.set(res.bookings.data.records
        .filter(r => !r['end_date'] || String(r['end_date']).slice(0, 10) >= from)
        .map(r => ({
          id: String(r['id']),
          userId: String(r['user_id'] ?? ''),
          regardingEntity: (r['regarding_entity'] as string | null) ?? null,
          regardingId: (r['regarding_id'] as string | null) ?? null,
          percent: Number(r['allocation_percent'] ?? 0),
          start: String(r['start_date'] ?? from),
          end: (r['end_date'] as string | null) ?? null,
          rowVersion: Number(r['row_version'] ?? 0),
        })));
      this.leave.set(res.leave.data.records.map(r => ({
        userId: String(r['user_id'] ?? ''),
        start: String(r['leave_start'] ?? from),
        end: String(r['leave_end'] ?? to),
      })));
    });
  }
}
