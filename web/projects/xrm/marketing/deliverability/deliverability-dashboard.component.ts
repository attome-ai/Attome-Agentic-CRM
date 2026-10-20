import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { ApiError, LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import { catchError, of } from 'rxjs';

import {
  DeliverabilityOverview, DeliverabilityService, PrecheckReport, ProviderDay,
} from './deliverability.service';
import { GuidancePanelComponent } from './guidance-panel.component';
import { PrecheckPanelComponent } from './precheck-panel.component';

/** The rate a chart draws. */
export type RateMetric = 'delivered' | 'bounced' | 'complaints';

/** One provider's line on a rate chart. */
export interface RateSeries {
  provider: string;
  /** Percent of sent, one per day in `days`; null where nothing was sent. */
  rates: (number | null)[];
}

/** The chart's frame. */
const W = 600;
const H = 160;

/** Every day with figures, ascending, and each provider's rate per day. Pure. */
export function rateSeries(rows: readonly ProviderDay[], metric: RateMetric): { days: string[]; series: RateSeries[] } {
  const days = [...new Set(rows.map(r => r.day))].sort();
  const providers = [...new Set(rows.map(r => r.mailbox_provider))].sort();
  const series = providers.map(provider => ({
    provider,
    rates: days.map(day => {
      const r = rows.find(x => x.day === day && x.mailbox_provider === provider);
      return r && r.sent > 0 ? (r[metric] * 100) / r.sent : null;
    }),
  }));
  return { days, series };
}

/** The chart's top: the highest rate or the limit, whichever is larger, with headroom. Pure. */
export function chartMax(series: readonly RateSeries[], limit: number | null): number {
  const top = Math.max(limit ?? 0, ...series.flatMap(s => s.rates.filter((r): r is number => r !== null)));
  return top > 0 ? top * 1.15 : 1;
}

/** SVG points for one series; days with no figure break nothing, they are skipped. Pure. */
export function linePoints(rates: readonly (number | null)[], max: number): string {
  const step = rates.length > 1 ? W / (rates.length - 1) : 0;
  return rates
    .map((r, i) => (r === null ? null : `${(i * step).toFixed(1)},${(H - (r / max) * H).toFixed(1)}`))
    .filter((p): p is string => p !== null)
    .join(' ');
}

/** A chart as the template draws it. */
interface Chart {
  key: string;
  limit: number | null;
  days: string[];
  max: number;
  lines: { provider: string; points: string; colour: number }[];
  limitY: number | null;
}

/**
 * The email deliverability dashboard (roadmap E6-T13): per mailbox provider
 * and day, the delivered, bounce and complaint rates, the last two with the
 * policy's limits drawn across them (2% and 0.3% unless the policy says
 * otherwise); the largest sends; blocklist status; each domain's DMARC pass
 * share; the alerts with their guidance; and a pre-send check of a pasted
 * message. Everything reads `GET /api/v1/marketing/deliverability/overview`
 * and `POST /api/v1/marketing/precheck`; the route is gated on the
 * marketing module and `marketing_deliverability_policy.read`. Arabic
 * mirrors the layout and the time axis; figures stay left to right.
 */
@Component({
  selector: 'xrm-deliverability-dashboard',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DecimalPipe, LocalNumberPipe, TranslatePipe, GuidancePanelComponent, PrecheckPanelComponent],
  template: `
    <section class="dd" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="dd-title">
      <header class="dd-head">
        <h2 id="dd-title">{{ 'marketingDeliverability.title' | translate }}</h2>
        <label>{{ 'marketingDeliverability.window' | translate }}
          <select data-testid="dd-days" [value]="days()" (change)="setDays($event)">
            @for (d of windows; track d) { <option [value]="d">{{ d | localNumber }} {{ 'marketingDeliverability.days' | translate }}</option> }
          </select>
        </label>
      </header>
      @if (error(); as message) { <p class="dd-error" role="alert">{{ message }}</p> }

      @if (overview(); as o) {
        <div class="dd-charts">
          @for (c of charts(); track c.key) {
            <figure class="dd-chart" [attr.data-testid]="'dd-chart-' + c.key">
              <figcaption>
                {{ 'marketingDeliverability.chart.' + c.key | translate }}
                @if (c.limit !== null) {
                  · {{ 'marketingDeliverability.limit' | translate }} <span dir="ltr">{{ c.limit | number: '1.0-2' }}%</span>
                }
              </figcaption>
              @if (c.days.length) {
                <svg [attr.viewBox]="'0 0 ' + w + ' ' + h" preserveAspectRatio="none" role="img"
                     [attr.aria-label]="'marketingDeliverability.chart.' + c.key | translate">
                  <g [attr.transform]="lang.isRtl() ? 'translate(' + w + ',0) scale(-1,1)' : null">
                    @if (c.limitY !== null) {
                      <line class="dd-limit" data-testid="dd-limit" x1="0" [attr.x2]="w" [attr.y1]="c.limitY" [attr.y2]="c.limitY" />
                    }
                    @for (l of c.lines; track l.provider) {
                      <polyline [attr.class]="'dd-line dd-c' + l.colour" [attr.points]="l.points" />
                    }
                  </g>
                </svg>
                <ul class="dd-legend">
                  @for (l of c.lines; track l.provider) {
                    <li><span [attr.class]="'dd-swatch dd-c' + l.colour"></span><span dir="ltr">{{ l.provider }}</span></li>
                  }
                </ul>
                <p class="dd-axis"><span dir="ltr">{{ c.days[0] }}</span><span dir="ltr">{{ c.days[c.days.length - 1] }}</span></p>
              } @else {
                <p class="dd-empty">{{ 'marketingDeliverability.noData' | translate }}</p>
              }
            </figure>
          }
        </div>

        <xrm-deliverability-guidance [alerts]="o.alerts" />

        <h3>{{ 'marketingDeliverability.sends' | translate }}</h3>
        @if (o.sends.length) {
          <table class="dd-table" data-testid="dd-sends">
            <thead><tr>
              <th scope="col">{{ 'marketingDeliverability.send' | translate }}</th>
              <th scope="col">{{ 'marketingDeliverability.sent' | translate }}</th>
              <th scope="col">{{ 'marketingDeliverability.deliveredRate' | translate }}</th>
              <th scope="col">{{ 'marketingDeliverability.bounceRate' | translate }}</th>
              <th scope="col">{{ 'marketingDeliverability.complaintRate' | translate }}</th>
            </tr></thead>
            <tbody>
              @for (s of o.sends; track s.send_ref) {
                <tr>
                  <td dir="ltr">{{ s.send_ref }}</td>
                  <td>{{ s.sent | localNumber }}</td>
                  <td dir="ltr">{{ pct(s.delivered, s.sent) }}</td>
                  <td dir="ltr" [class.dd-over]="over(s.bounced, s.sent, o.bounce_limit)">{{ pct(s.bounced, s.sent) }}</td>
                  <td dir="ltr" [class.dd-over]="over(s.complaints, s.sent, o.complaint_limit)">{{ pct(s.complaints, s.sent) }}</td>
                </tr>
              }
            </tbody>
          </table>
        } @else { <p class="dd-empty">{{ 'marketingDeliverability.noData' | translate }}</p> }

        <div class="dd-two">
          <div>
            <h3>{{ 'marketingDeliverability.blocklist' | translate }}</h3>
            @if (o.blocklist.length) {
              <table class="dd-table" data-testid="dd-blocklist">
                <tbody>
                  @for (b of o.blocklist; track b.target + b.list_name) {
                    <tr [class.dd-over]="b.listed">
                      <td dir="ltr">{{ b.target }}</td>
                      <td dir="ltr">{{ b.list_name }}</td>
                      <td>{{ (b.listed ? 'marketingDeliverability.listed' : 'marketingDeliverability.clean') | translate }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            } @else { <p class="dd-empty">{{ 'marketingDeliverability.noData' | translate }}</p> }
          </div>
          <div>
            <h3>{{ 'marketingDeliverability.dmarc' | translate }}</h3>
            @if (o.dmarc.length) {
              <table class="dd-table" data-testid="dd-dmarc">
                <tbody>
                  @for (d of o.dmarc; track d.domain) {
                    <tr>
                      <td dir="ltr">{{ d.domain }}</td>
                      <td>{{ d.messages | localNumber }}</td>
                      <td dir="ltr">{{ pct(d.passed, d.messages) }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            } @else { <p class="dd-empty">{{ 'marketingDeliverability.noData' | translate }}</p> }
          </div>
        </div>
      }

      <form class="dd-check" (submit)="check($event)">
        <h3>{{ 'marketingDeliverability.checkMessage' | translate }}</h3>
        <label>{{ 'marketingDeliverability.html' | translate }}
          <textarea dir="ltr" rows="6" data-testid="dd-html" [value]="html()" (input)="html.set(text($event))"></textarea></label>
        <label>{{ 'marketingDeliverability.text' | translate }}
          <textarea rows="3" [value]="plain()" (input)="plain.set(text($event))"></textarea></label>
        <button type="submit" [disabled]="!html().trim() || checking()">{{ 'marketingDeliverability.runCheck' | translate }}</button>
      </form>
      <xrm-deliverability-precheck [report]="report()" />
    </section>
  `,
  styles: [`
    .dd { display: grid; gap: var(--space-4, 1rem); }
    .dd-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: var(--space-2, .5rem); }
    .dd-charts { display: grid; gap: var(--space-4, 1rem); grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr)); }
    .dd-chart { margin: 0; border: 1px solid var(--color-border, #ddd); border-radius: 6px; padding: var(--space-2, .5rem); }
    .dd-chart svg { inline-size: 100%; block-size: 10rem; display: block; }
    .dd-line { fill: none; stroke-width: 2; vector-effect: non-scaling-stroke; }
    .dd-limit { stroke: var(--color-danger, #c53030); stroke-dasharray: 6 4; stroke-width: 1.5; vector-effect: non-scaling-stroke; }
    .dd-c0 { stroke: var(--color-primary, #2b6cb0); background: var(--color-primary, #2b6cb0); }
    .dd-c1 { stroke: var(--color-accent, #805ad5); background: var(--color-accent, #805ad5); }
    .dd-c2 { stroke: var(--color-success, #2f855a); background: var(--color-success, #2f855a); }
    .dd-c3 { stroke: var(--color-warning, #b7791f); background: var(--color-warning, #b7791f); }
    .dd-c4 { stroke: var(--color-text-secondary, #666); background: var(--color-text-secondary, #666); }
    .dd-legend { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: var(--space-2, .5rem); font-size: .875rem; }
    .dd-swatch { display: inline-block; inline-size: .75rem; block-size: .75rem; margin-inline-end: .25rem; border-radius: 2px; }
    .dd-axis { display: flex; justify-content: space-between; margin: 0; font-size: .75rem; color: var(--color-text-secondary, #666); }
    .dd-table { inline-size: 100%; border-collapse: collapse; }
    .dd-table th, .dd-table td { text-align: start; padding-block: .25rem; padding-inline: .5rem; border-block-end: 1px solid var(--color-border, #ddd); }
    .dd-over { color: var(--color-danger, #c53030); }
    .dd-two { display: grid; gap: var(--space-4, 1rem); grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }
    .dd-check { display: grid; gap: var(--space-2, .5rem); }
    .dd-check textarea { inline-size: 100%; }
    .dd-error { color: var(--color-danger, #c53030); }
    .dd-empty { color: var(--color-text-secondary, #666); }
  `],
})
export class DeliverabilityDashboardComponent {
  private readonly service = inject(DeliverabilityService);
  protected readonly lang = inject(LangService);
  protected readonly w = W;
  protected readonly h = H;
  protected readonly windows = [7, 30, 90];

  protected readonly days = signal(30);
  protected readonly overview = signal<DeliverabilityOverview | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly html = signal('');
  protected readonly plain = signal('');
  protected readonly checking = signal(false);
  protected readonly report = signal<PrecheckReport | null>(null);

  protected readonly charts = computed<Chart[]>(() => {
    const o = this.overview();
    if (!o) return [];
    const spec: { key: string; metric: RateMetric; limit: number | null }[] = [
      { key: 'delivered', metric: 'delivered', limit: null },
      { key: 'bounce', metric: 'bounced', limit: o.bounce_limit },
      { key: 'complaint', metric: 'complaints', limit: o.complaint_limit },
    ];
    return spec.map(({ key, metric, limit }) => {
      const { days, series } = rateSeries(o.providers, metric);
      const max = chartMax(series, limit);
      return {
        key,
        limit,
        days,
        max,
        lines: series.map((s, i) => ({ provider: s.provider, points: linePoints(s.rates, max), colour: i % 5 })),
        limitY: limit === null ? null : H - (limit / max) * H,
      };
    });
  });

  constructor() {
    this.load();
  }

  protected setDays(event: Event): void {
    this.days.set(Number((event.target as HTMLSelectElement).value) || 30);
    this.load();
  }

  protected text(event: Event): string {
    return (event.target as HTMLTextAreaElement).value;
  }

  protected pct(part: number, whole: number): string {
    return whole > 0 ? `${((part * 100) / whole).toFixed(2)}%` : '–';
  }

  protected over(part: number, whole: number, limit: number): boolean {
    return whole > 0 && (part * 100) / whole > limit;
  }

  protected check(event: Event): void {
    event.preventDefault();
    if (!this.html().trim()) return;
    this.checking.set(true);
    this.service.precheck({ html: this.html(), text: this.plain().trim() || null }).pipe(
      catchError((e: unknown) => {
        this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(r => {
      this.checking.set(false);
      if (r) this.report.set(r);
    });
  }

  private load(): void {
    this.error.set(null);
    this.service.overview(this.days()).pipe(
      catchError((e: unknown) => {
        this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(o => this.overview.set(o));
  }
}
