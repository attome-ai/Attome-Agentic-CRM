import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiComponents, ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { catchError, forkJoin, map, of } from 'rxjs';

type SubscriptionAsOf = ApiComponents['schemas']['SubscriptionAsOf'];

/** One segment of a line: what it was from one date to the next. */
export interface TimelineSegment {
  from: string;
  /** Open-ended when absent. */
  to: string | null;
  quantity: number | null;
  unitPrice: number | null;
  kind: string | null;
}

/** One line's row. */
export interface TimelineRow {
  lineId: string;
  label: string;
  segments: TimelineSegment[];
}

/** Where a segment sits on the axis, as percentages of its length. */
export interface Placed {
  start: number;
  width: number;
}

const DAY = 86_400_000;
const day = (iso: string) => Date.parse(iso.slice(0, 10) + 'T00:00:00Z');

/** The axis from the first segment's start to the last end (or `asOf`,
 *  whichever is later, plus a day so an open segment shows). Pure. */
export function axis(rows: readonly TimelineRow[], asOf: string): { start: number; end: number } {
  const starts = rows.flatMap(r => r.segments.map(s => day(s.from)));
  const ends = rows.flatMap(r => r.segments.map(s => (s.to ? day(s.to) : day(asOf))));
  const start = Math.min(day(asOf), ...starts);
  const end = Math.max(day(asOf) + DAY, ...ends);
  return { start, end: end > start ? end : start + DAY };
}

/** A segment's place on the axis; an open segment runs to the axis end. Pure. */
export function place(seg: TimelineSegment, start: number, end: number): Placed {
  const span = end - start;
  const from = Math.max(start, day(seg.from));
  const to = Math.min(end, seg.to ? day(seg.to) : end);
  return {
    start: ((from - start) / span) * 100,
    width: Math.max(0.5, ((to - from) / span) * 100),
  };
}

/**
 * A subscription's lines over time (roadmap F3-T14): one row per line, its
 * segments laid on a date axis, and a marker at the chosen date with each
 * line's quantity and price in force that day (from
 * `GET /api/v1/billing/subscriptions/{id}?as_of=`). Positions are custom
 * properties read by logical insets (`inset-inline-start`), so the axis
 * starts on the right in Arabic. Dates follow the
 * user's calendar (Gregorian or Hijri) through the date pipe.
 */
@Component({
  selector: 'xrm-billing-subscription-timeline',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe],
  template: `
    <section class="st" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="st-title" data-testid="st">
      <h3 id="st-title">{{ 'billingSubscriptionTimeline.title' | translate }}</h3>
      @if (error(); as message) { <p class="st-error" role="alert">{{ message }}</p> }
      @if (rows().length) {
        <div class="st-axis" data-testid="st-axis">
          <span class="st-axis-start" data-testid="st-axis-start">{{ bounds().start | localDate: { dateStyle: 'medium', timeZone: 'UTC' } }}</span>
          <span class="st-axis-end">{{ bounds().end | localDate: { dateStyle: 'medium', timeZone: 'UTC' } }}</span>
        </div>
        @for (r of rows(); track r.lineId) {
          <div class="st-row" data-testid="st-row">
            <span class="st-label">{{ r.label }}</span>
            <div class="st-track">
              @for (s of r.segments; track s.from) {
                <span class="st-seg" [attr.data-kind]="s.kind"
                  [style.--st-start]="place(s).start + '%'" [style.--st-width]="place(s).width + '%'"
                  [attr.title]="(s.from | localDate: { dateStyle: 'medium', timeZone: 'UTC' })">
                  @if (s.quantity !== null) { <span dir="ltr">{{ s.quantity }}</span> }
                </span>
              }
              <span class="st-now" [style.--st-start]="nowAt() + '%'" aria-hidden="true"></span>
            </div>
            <span class="st-asof">
              @if (current(r.lineId); as c) {
                {{ 'billingSubscriptionTimeline.quantity' | translate }} <span dir="ltr">{{ c.quantity }}</span>
                · {{ 'billingSubscriptionTimeline.price' | translate }} <span dir="ltr">{{ c.unit_price }}</span>
              } @else {
                {{ 'billingSubscriptionTimeline.notInForce' | translate }}
              }
            </span>
          </div>
        }
      } @else if (loaded()) {
        <p class="st-muted">{{ 'billingSubscriptionTimeline.empty' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .st { display: flex; flex-direction: column; gap: var(--space-2, 8px); }
    .st-axis { display: flex; justify-content: space-between; margin-inline-start: 10rem; color: var(--color-text-secondary); }
    .st-row { display: grid; grid-template-columns: 10rem 1fr 12rem; align-items: center; gap: var(--space-2, 8px); }
    .st-track { position: relative; block-size: 1.5rem; background: var(--color-surface-muted, transparent); border: 1px solid var(--color-border); }
    .st-seg { position: absolute; inset-block: 0; inset-inline-start: var(--st-start); inline-size: var(--st-width); background: var(--color-primary-soft, var(--color-border)); border-inline-end: 1px solid var(--color-border); overflow: hidden; font-size: 0.75rem; padding-inline-start: var(--space-1, 4px); }
    .st-now { position: absolute; inset-block: 0; inset-inline-start: var(--st-start); inline-size: 2px; background: var(--color-danger); }
    .st-asof, .st-muted { color: var(--color-text-secondary); }
    .st-error { color: var(--color-danger); margin: 0; }
  `],
})
export class SubscriptionTimelineComponent {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);
  protected readonly lang = inject(LangService);

  readonly subscriptionId = input.required<string>();
  /** The date to show the lines as of (`YYYY-MM-DD`); today when absent. */
  readonly asOf = input<string | null>(null);

  readonly rows = signal<TimelineRow[]>([]);
  readonly asOfLines = signal<SubscriptionAsOf['lines']>([]);
  readonly loaded = signal(false);
  readonly error = signal<string | null>(null);

  readonly day = computed(() => this.asOf() ?? new Date().toISOString().slice(0, 10));
  readonly bounds = computed(() => axis(this.rows(), this.day()));
  readonly nowAt = computed(() => {
    const { start, end } = this.bounds();
    return ((day(this.day()) - start) / (end - start)) * 100;
  });

  constructor() {
    effect(() => {
      const id = this.subscriptionId();
      const asOf = this.day();
      untracked(() => this.load(id, asOf));
    });
  }

  place(seg: TimelineSegment): Placed {
    const { start, end } = this.bounds();
    return place(seg, start, end);
  }

  current(lineId: string) {
    return this.asOfLines().find(l => l.line_id === lineId && l.quantity !== null && l.quantity !== undefined) ?? null;
  }

  private load(id: string, asOf: string): void {
    this.error.set(null);
    this.api.get<SubscriptionAsOf>(`/api/v1/billing/subscriptions/${encodeURIComponent(id)}`, { as_of: asOf })
      .subscribe({
        next: view => {
          this.asOfLines.set(view.lines);
          if (!view.lines.length) {
            this.rows.set([]);
            this.loaded.set(true);
            return;
          }
          forkJoin(view.lines.map((line, i) => this.entities.list('subscription_segment', {
            filters: [{ field: 'line_ref', op: 'eq', value: line.line_id }],
            sorts: [{ field: 'valid_from', dir: 'asc' }],
            limit: 200,
          }).pipe(
            map(res => ({
              lineId: line.line_id,
              label: `${this.lang.translate('billingSubscriptionTimeline.line')} ${i + 1}`,
              segments: res.data
                .map(s => s.data as Record<string, unknown>)
                .filter(d => typeof d['valid_from'] === 'string')
                .map(d => ({
                  from: d['valid_from'] as string,
                  to: typeof d['valid_to'] === 'string' ? d['valid_to'] : null,
                  quantity: d['quantity'] == null ? null : Number(d['quantity']),
                  unitPrice: d['unit_price'] == null ? null : Number(d['unit_price']),
                  kind: typeof d['change_kind'] === 'string' ? d['change_kind'] : null,
                })),
            })),
            catchError(() => of({ lineId: line.line_id, label: `${i + 1}`, segments: [] as TimelineSegment[] })),
          ))).subscribe(rows => {
            this.rows.set(rows);
            this.loaded.set(true);
          });
        },
        error: (e: ApiError) => {
          this.loaded.set(true);
          this.error.set(this.lang.errorText(e));
        },
      });
  }
}
