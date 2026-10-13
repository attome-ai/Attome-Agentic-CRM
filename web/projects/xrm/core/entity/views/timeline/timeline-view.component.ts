import { ChangeDetectionStrategy, Component, effect, inject, input, output, signal, untracked } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  AvailableView, CalendarViewMetadata, QueryService, ViewAdminService,
} from '@attome/xrm/core/query/data';

interface TimelineBar {
  id:      string;
  title:   string;
  /** Fraction of the visible window, 0..1. */
  leftPct:  number;
  widthPct: number;
  colorClass: string;
}

/** Same shape as `calendar-view.component.ts`'s local filter type. */
interface DateRangeFilter { field: string; op: string; value?: string }

const COLOR_CLASSES = ['xrm-tl-c0', 'xrm-tl-c1', 'xrm-tl-c2', 'xrm-tl-c3', 'xrm-tl-c4', 'xrm-tl-c5'];

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
function addDays(d: Date, n: number): Date {
  const r = new Date(d); r.setDate(r.getDate() + n); return r;
}

const DATE_ONLY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** Same reasoning as `calendar-view.component.ts`'s identical helper: a bare
 * `YYYY-MM-DD` value parses as UTC midnight by default, which is the
 * previous local calendar day for anyone west of UTC. */
function parseRecordDate(raw: string): Date | null {
  const dateOnly = DATE_ONLY_RE.exec(raw);
  if (dateOnly) {
    const [, y, m, d] = dateOnly;
    return new Date(Number(y), Number(m) - 1, Number(d));
  }
  const parsed = new Date(raw);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

const WINDOW_DAYS = 21;

/**
 * `kind = timeline` (D-429/M64): Gantt-lite over the same feed
 * `kind = calendar` uses — one bar per record, positioned within a rolling
 * `WINDOW_DAYS`-wide window by `start_field`/`end_field`. Same privilege +
 * record-security posture as the calendar view: this is `query/execute`
 * against the view's own bound (and already-gated) stored query, not a
 * separate feed.
 */
@Component({
  selector:   'xrm-timeline-view',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe],
  templateUrl: './timeline-view.component.html',
  styleUrl:    './timeline-view.component.css',
})
export class TimelineViewComponent {
  readonly entityName = input.required<string>();
  readonly viewId = input<string | null>(null);
  readonly recordClick = output<string>();

  private readonly querySvc = inject(QueryService);
  private readonly viewSvc  = inject(ViewAdminService);
  private readonly lang     = inject(LangService);

  readonly loading = signal(false);
  readonly error   = signal<string | null>(null);
  readonly view    = signal<AvailableView | null>(null);
  readonly bars    = signal<TimelineBar[]>([]);
  readonly days    = signal<Date[]>([]);
  readonly windowStart = signal(toDateOnly(new Date()));

  constructor() {
    effect(() => {
      this.entityName();
      this.viewId();
      untracked(() => this.resolveView());
    });
    effect(() => {
      const start = this.windowStart();
      const view = this.view();
      if (view) untracked(() => this.loadWindow(view, start));
    });
  }

  previousWindow(): void { this.windowStart.set(addDays(this.windowStart(), -WINDOW_DAYS)); }
  nextWindow(): void { this.windowStart.set(addDays(this.windowStart(), WINDOW_DAYS)); }
  today(): void { this.windowStart.set(toDateOnly(new Date())); }

  private resolveView(): void {
    this.loading.set(true);
    this.error.set(null);
    this.viewSvc.listAvailable(this.entityName()).subscribe({
      next: views => {
        const requested = this.viewId();
        const target = requested
          ? views.find(v => v.id === requested && v.kind === 'timeline')
          : views.find(v => v.kind === 'timeline');
        if (!target) {
          this.loading.set(false);
          this.error.set(this.lang.translate('entityViews.timeline.noView'));
          return;
        }
        this.view.set(target);
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }

  private loadWindow(view: AvailableView, windowStart: Date): void {
    const meta = view.view_metadata as unknown as CalendarViewMetadata;
    if (!meta.start_field) {
      this.loading.set(false);
      this.error.set(this.lang.translate('entityViews.timeline.noFields'));
      return;
    }
    const endField = meta.end_field || meta.start_field;
    const windowEnd = addDays(windowStart, WINDOW_DAYS - 1);

    const days: Date[] = [];
    for (let i = 0; i < WINDOW_DAYS; i++) days.push(addDays(windowStart, i));
    this.days.set(days);

    this.loading.set(true);
    this.error.set(null);
    const filters: DateRangeFilter[] = [
      { field: endField, op: 'gte', value: isoDate(windowStart) },
      { field: meta.start_field, op: 'lte', value: isoDate(windowEnd) },
    ];

    this.querySvc.execute({
      view_id: view.id, page: 1, page_size: 500, include_total: true, filters,
    }).subscribe({
      next: res => {
        const titleField = res.data.columns.find(c => c.is_visible)?.name;
        const totalMs = windowEnd.getTime() + 86_400_000 - windowStart.getTime();
        const bars: TimelineBar[] = [];
        for (const r of res.data.records) {
          const startRaw = r[meta.start_field];
          const start = startRaw ? parseRecordDate(String(startRaw)) : null;
          if (!start) continue;
          const endRaw = r[endField];
          const end = (endRaw ? parseRecordDate(String(endRaw)) : null) ?? start;
          const clampedStart = start.getTime() < windowStart.getTime() ? windowStart : start;
          const clampedEnd = end.getTime() > windowEnd.getTime() ? addDays(windowEnd, 1) : addDays(end, 1);
          const leftPct = Math.max(0, (clampedStart.getTime() - windowStart.getTime()) / totalMs);
          const widthPct = Math.max(0.01, (clampedEnd.getTime() - clampedStart.getTime()) / totalMs);
          bars.push({
            id: String(r['id'] ?? ''),
            title: titleField ? String(r[titleField] ?? '') : String(r['id'] ?? ''),
            leftPct, widthPct,
            colorClass: colorClassFor(meta.color_field ? r[meta.color_field] : null),
          });
        }
        this.bars.set(bars);
        this.loading.set(false);
      },
      error: (e: ApiError) => { this.loading.set(false); this.error.set(e.message); },
    });
  }

  onBarClick(bar: TimelineBar): void { this.recordClick.emit(bar.id); }
}
