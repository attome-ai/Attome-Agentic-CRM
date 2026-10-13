import { ChangeDetectionStrategy, Component, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  AvailableView, CalendarViewMetadata, QueryService, ViewAdminService,
} from '@attome/xrm/core/query/data';

/** One entry of `query/execute`'s `filters` array — same shape as
 * `entity-list.component.ts`'s local `QueryFilter`, redeclared here rather
 * than imported (that one lives in `core/entity/list`, not `core/query/data`,
 * and pulling it in would be a needless cross-file coupling for three fields). */
interface DateRangeFilter { field: string; op: string; value?: string }

interface CalendarEvent {
  id:      string;
  title:   string;
  start:   Date;
  colorClass: string;
}

interface CalendarDay {
  date:      Date;
  inMonth:   boolean;
  isToday:   boolean;
  events:    CalendarEvent[];
}

const COLOR_CLASSES = ['xrm-cal-c0', 'xrm-cal-c1', 'xrm-cal-c2', 'xrm-cal-c3', 'xrm-cal-c4', 'xrm-cal-c5'];

function colorClassFor(value: unknown): string {
  if (value === null || value === undefined || value === '') return COLOR_CLASSES[0];
  const s = String(value);
  let hash = 0;
  for (let i = 0; i < s.length; i++) hash = (hash * 31 + s.charCodeAt(i)) >>> 0;
  return COLOR_CLASSES[hash % COLOR_CLASSES.length];
}

function toDateOnly(d: Date): Date { return new Date(d.getFullYear(), d.getMonth(), d.getDate()); }
function isoDate(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

const DATE_ONLY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** A bare `YYYY-MM-DD` value (the shape PostgreSQL's `date` type comes back
 * as) carries no zone — parsing it with the platform `Date` constructor
 * reads it as UTC midnight, which is the PREVIOUS local calendar day for
 * anyone west of UTC. Same bug class `entity-list.component.ts`'s
 * `formatDateCell` already guards against; parsed as local-midnight
 * components instead so a record's day placement never shifts by timezone.
 * A full timestamp (has a `T`/time component) is left to the normal
 * constructor, which is timezone-correct for those already. */
function parseRecordDate(raw: string): Date | null {
  const dateOnly = DATE_ONLY_RE.exec(raw);
  if (dateOnly) {
    const [, y, m, d] = dateOnly;
    return new Date(Number(y), Number(m) - 1, Number(d));
  }
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function sameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
}

/**
 * `kind = calendar` (D-429/M64): renders a month grid over the view's own
 * bound query — the SAME `POST /api/v1/query/execute` path a `kind = list`
 * view uses, filtered to the visible month via `start_field`/`end_field`.
 * That path already applies the view's `required_privilege` gate and, for a
 * single-entity view, `attome_security::rls_predicate` (D-133) — this component
 * adds no security logic of its own, it inherits the feed's.
 */
@Component({
  selector:   'xrm-calendar-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  templateUrl: './calendar-view.component.html',
  styleUrl:    './calendar-view.component.css',
})
export class CalendarViewComponent {
  readonly entityName = input.required<string>();
  readonly viewId = input<string | null>(null);
  readonly recordClick = output<string>();

  private readonly querySvc = inject(QueryService);
  private readonly viewSvc  = inject(ViewAdminService);
  private readonly lang     = inject(LangService);

  readonly loading = signal(false);
  readonly error   = signal<string | null>(null);
  readonly view    = signal<AvailableView | null>(null);
  readonly weeks   = signal<CalendarDay[][]>([]);
  readonly monthAnchor = signal(toDateOnly(new Date()));

  readonly monthLabel = signal('');

  constructor() {
    effect(() => {
      this.entityName();
      this.viewId();
      untracked(() => this.resolveView());
    });
    effect(() => {
      const anchor = this.monthAnchor();
      const view = this.view();
      if (view) untracked(() => this.loadMonth(view, anchor));
    });
  }

  previousMonth(): void {
    const a = this.monthAnchor();
    this.monthAnchor.set(new Date(a.getFullYear(), a.getMonth() - 1, 1));
  }

  nextMonth(): void {
    const a = this.monthAnchor();
    this.monthAnchor.set(new Date(a.getFullYear(), a.getMonth() + 1, 1));
  }

  today(): void { this.monthAnchor.set(toDateOnly(new Date())); }

  private resolveView(): void {
    this.loading.set(true);
    this.error.set(null);
    this.viewSvc.listAvailable(this.entityName()).subscribe({
      next: views => {
        const requested = this.viewId();
        const target = requested
          ? views.find(v => v.id === requested && v.kind === 'calendar')
          : views.find(v => v.kind === 'calendar');
        if (!target) {
          this.loading.set(false);
          this.error.set(this.lang.translate('entityViews.calendar.noView'));
          return;
        }
        this.view.set(target);
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }

  private loadMonth(view: AvailableView, anchor: Date): void {
    const meta = view.view_metadata as unknown as CalendarViewMetadata;
    if (!meta.start_field) {
      this.loading.set(false);
      this.error.set(this.lang.translate('entityViews.calendar.noFields'));
      return;
    }
    const endField = meta.end_field || meta.start_field;

    const gridStart = new Date(anchor.getFullYear(), anchor.getMonth(), 1);
    gridStart.setDate(gridStart.getDate() - gridStart.getDay());
    const gridEnd = new Date(gridStart);
    gridEnd.setDate(gridStart.getDate() + 41); // 6 weeks

    this.monthLabel.set(anchor.toLocaleDateString(undefined, { month: 'long', year: 'numeric' }));
    this.loading.set(true);
    this.error.set(null);

    const filters: DateRangeFilter[] = [
      { field: endField, op: 'gte', value: isoDate(gridStart) },
      { field: meta.start_field, op: 'lte', value: isoDate(gridEnd) },
    ];

    this.querySvc.execute({
      view_id: view.id, page: 1, page_size: 500, include_total: true, filters,
    }).subscribe({
      next: res => {
        const titleField = res.data.columns.find(c => c.is_visible)?.name;
        const events: CalendarEvent[] = res.data.records
          .map(r => {
            const raw = r[meta.start_field];
            const start = raw ? parseRecordDate(String(raw)) : null;
            if (!start) return null;
            return {
              id: String(r['id'] ?? ''),
              title: titleField ? String(r[titleField] ?? '') : String(r['id'] ?? ''),
              start,
              colorClass: colorClassFor(meta.color_field ? r[meta.color_field] : null),
            } satisfies CalendarEvent;
          })
          .filter((e): e is CalendarEvent => e !== null);

        const today = toDateOnly(new Date());
        const days: CalendarDay[] = [];
        for (let i = 0; i < 42; i++) {
          const date = new Date(gridStart);
          date.setDate(gridStart.getDate() + i);
          days.push({
            date,
            inMonth: date.getMonth() === anchor.getMonth(),
            isToday: sameDay(date, today),
            events: events.filter(e => sameDay(e.start, date)),
          });
        }
        const weeks: CalendarDay[][] = [];
        for (let i = 0; i < 6; i++) weeks.push(days.slice(i * 7, i * 7 + 7));
        this.weeks.set(weeks);
        this.loading.set(false);
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }

  onEventClick(ev: CalendarEvent): void { this.recordClick.emit(ev.id); }
}
