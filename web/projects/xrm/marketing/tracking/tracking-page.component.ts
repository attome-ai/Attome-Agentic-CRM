import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ATTOME_CONFIG, ApiError, LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import { catchError, of } from 'rxjs';

import { LiveVisitor, ReportRow, TrackedSite, TrackingReport, TrackingService } from './tracking.service';

/** The snippet that loads the tracking script for `siteKey` from `base`. Pure. */
export function embedSnippet(base: string, siteKey: string): string {
  const origin = base.replace(/\/+$/, '');
  return `<script async src="${origin}/api/v1/track/script.js?site=${encodeURIComponent(siteKey)}"></script>`;
}

/** Each row's share of the largest, in percent, for the bars. Pure. */
export function barShares(rows: readonly ReportRow[]): number[] {
  const top = Math.max(0, ...rows.map(r => r.visits));
  return rows.map(r => (top > 0 ? Math.round((r.visits * 100) / top) : 0));
}

/** One top list as the template draws it. */
interface TopList {
  key: 'sources' | 'landingPages' | 'campaigns';
  rows: { label: string; visits: number; share: number }[];
}

/**
 * Website tracking (roadmap E14-T12): for one tracked site, the embed code
 * to paste on its pages, its visits over a period (how many, how many by a
 * known contact or lead, the top sources, landing pages and campaigns) and
 * who is on the site now. Sites themselves are records, edited on their
 * generic form (the "Tracked sites" link). Reads `POST /api/v1/query/execute`
 * for the sites, `GET /api/v1/marketing/tracking/report` and
 * `GET /api/v1/marketing/tracking/live`, all gated on
 * `marketing_tracked_site.read`. Arabic mirrors the layout; URLs and code
 * stay left to right.
 */
@Component({
  selector: 'xrm-tracking-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, RouterLink, TranslatePipe],
  template: `
    <section class="tp" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="tp-title">
      <header class="tp-head">
        <h2 id="tp-title">{{ 'marketingTracking.title' | translate }}</h2>
        <a routerLink="/xrm/entity/marketing_tracked_site/list">{{ 'marketingTracking.manageSites' | translate }}</a>
      </header>
      @if (error(); as message) { <p class="tp-error" role="alert">{{ message }}</p> }

      @if (sites().length === 0) {
        <p class="tp-empty" data-testid="tp-no-sites">{{ 'marketingTracking.noSites' | translate }}</p>
      } @else {
        <div class="tp-pickers">
          <label>{{ 'marketingTracking.site' | translate }}
            <select data-testid="tp-site" [value]="siteKey()" (change)="pickSite($event)">
              @for (s of sites(); track s.site_key) {
                <option [value]="s.site_key">{{ s.name ?? s.site_key }}</option>
              }
            </select>
          </label>
          <label>{{ 'marketingTracking.window' | translate }}
            <select data-testid="tp-days" [value]="days()" (change)="pickDays($event)">
              @for (d of windows; track d) {
                <option [value]="d">{{ d | localNumber }} {{ 'marketingTracking.days' | translate }}</option>
              }
            </select>
          </label>
        </div>

        <section class="tp-embed" aria-labelledby="tp-embed-title">
          <h3 id="tp-embed-title">{{ 'marketingTracking.embed' | translate }}</h3>
          <p class="tp-hint">{{ 'marketingTracking.embedHint' | translate }}</p>
          <pre dir="ltr" data-testid="tp-snippet"><code>{{ snippet() }}</code></pre>
          <button type="button" data-testid="tp-copy" (click)="copy()">
            {{ (copied() ? 'marketingTracking.copied' : 'marketingTracking.copy') | translate }}
          </button>
        </section>

        @if (report(); as r) {
          <div class="tp-totals" data-testid="tp-totals">
            <p><span class="tp-figure">{{ r.visits | localNumber }}</span> {{ 'marketingTracking.visits' | translate }}</p>
            <p><span class="tp-figure">{{ r.identified | localNumber }}</span> {{ 'marketingTracking.identified' | translate }}</p>
          </div>
          <div class="tp-lists">
            @for (list of lists(); track list.key) {
              <section class="tp-list" [attr.data-testid]="'tp-' + list.key">
                <h3>{{ 'marketingTracking.' + list.key | translate }}</h3>
                @if (list.rows.length) {
                  <ul>
                    @for (row of list.rows; track row.label) {
                      <li>
                        <span class="tp-label" dir="ltr">{{ row.label }}</span>
                        <span class="tp-bar" [style.inline-size.%]="row.share"></span>
                        <span class="tp-count">{{ row.visits | localNumber }}</span>
                      </li>
                    }
                  </ul>
                } @else {
                  <p class="tp-empty">{{ 'marketingTracking.noData' | translate }}</p>
                }
              </section>
            }
          </div>
        }

        <section class="tp-live" aria-labelledby="tp-live-title">
          <header class="tp-head">
            <h3 id="tp-live-title">{{ 'marketingTracking.live' | translate }}</h3>
            <button type="button" data-testid="tp-refresh" (click)="refreshLive()">{{ 'marketingTracking.refresh' | translate }}</button>
          </header>
          @if (live().length) {
            <table class="tp-table" data-testid="tp-live">
              <thead><tr>
                <th scope="col">{{ 'marketingTracking.page' | translate }}</th>
                <th scope="col">{{ 'marketingTracking.pages' | translate }}</th>
                <th scope="col">{{ 'marketingTracking.visitor' | translate }}</th>
                <th scope="col">{{ 'marketingTracking.lastSeen' | translate }}</th>
              </tr></thead>
              <tbody>
                @for (v of live(); track v.session_id) {
                  <tr>
                    <td dir="ltr">{{ v.current_url ?? '–' }}</td>
                    <td>{{ v.page_count | localNumber }}</td>
                    <td>{{ (v.contact_ref || v.lead_ref ? 'marketingTracking.known' : 'marketingTracking.anonymous') | translate }}</td>
                    <td>{{ time(v.last_seen_at) }}</td>
                  </tr>
                }
              </tbody>
            </table>
          } @else {
            <p class="tp-empty">{{ 'marketingTracking.noLive' | translate }}</p>
          }
        </section>
      }
    </section>
  `,
  styles: [`
    .tp { display: grid; gap: var(--space-4, 1rem); }
    .tp-head { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: var(--space-2, .5rem); }
    .tp-pickers { display: flex; flex-wrap: wrap; gap: var(--space-4, 1rem); }
    .tp-embed pre { margin: 0; padding: var(--space-2, .5rem); overflow-x: auto; background: var(--color-surface-alt, var(--color-surface)); border: 1px solid var(--color-border); border-radius: 6px; }
    .tp-hint, .tp-empty { color: var(--color-text-secondary); }
    .tp-totals { display: flex; flex-wrap: wrap; gap: var(--space-6, 1.5rem); }
    .tp-totals p { margin: 0; }
    .tp-figure { font-size: 1.5rem; font-weight: 600; margin-inline-end: .25rem; }
    .tp-lists { display: grid; gap: var(--space-4, 1rem); grid-template-columns: repeat(auto-fit, minmax(16rem, 1fr)); }
    .tp-list ul { list-style: none; margin: 0; padding: 0; display: grid; gap: .25rem; }
    .tp-list li { display: grid; grid-template-columns: minmax(0, 2fr) minmax(0, 1fr) auto; align-items: center; gap: .5rem; }
    .tp-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; text-align: start; }
    .tp-bar { display: block; block-size: .5rem; border-radius: 2px; background: var(--color-primary); }
    .tp-count { text-align: end; }
    .tp-table { inline-size: 100%; border-collapse: collapse; }
    .tp-table th, .tp-table td { text-align: start; padding-block: .25rem; padding-inline: .5rem; border-block-end: 1px solid var(--color-border); }
    .tp-error { color: var(--color-danger); }
  `],
})
export class TrackingPageComponent {
  private readonly service = inject(TrackingService);
  private readonly config = inject(ATTOME_CONFIG);
  protected readonly lang = inject(LangService);
  protected readonly windows = [7, 30, 90];

  readonly sites = signal<TrackedSite[]>([]);
  readonly siteKey = signal('');
  readonly days = signal(30);
  readonly report = signal<TrackingReport | null>(null);
  readonly live = signal<LiveVisitor[]>([]);
  readonly copied = signal(false);
  readonly error = signal<string | null>(null);

  readonly snippet = computed(() =>
    this.siteKey() ? embedSnippet(this.config.apiUrl || globalThis.location?.origin || '', this.siteKey()) : '');

  protected readonly lists = computed<TopList[]>(() => {
    const r = this.report();
    if (!r) return [];
    const list = (key: TopList['key'], rows: ReportRow[]): TopList => {
      const shares = barShares(rows);
      return { key, rows: rows.map((row, i) => ({ ...row, share: shares[i] })) };
    };
    return [list('sources', r.sources), list('landingPages', r.landing_pages), list('campaigns', r.campaigns)];
  });

  constructor() {
    this.service.sites().pipe(catchError(e => this.fail(e, [] as TrackedSite[]))).subscribe(sites => {
      this.sites.set(sites);
      const first = sites.find(s => s.enabled) ?? sites[0];
      if (first) this.select(first.site_key);
    });
  }

  protected pickSite(event: Event): void {
    this.select((event.target as HTMLSelectElement).value);
  }

  protected pickDays(event: Event): void {
    this.days.set(Number((event.target as HTMLSelectElement).value) || 30);
    this.loadReport();
  }

  /** Shows `siteKey`'s embed code, report and live visitors. */
  select(siteKey: string): void {
    this.siteKey.set(siteKey);
    this.copied.set(false);
    this.loadReport();
    this.refreshLive();
  }

  refreshLive(): void {
    const site = this.siteKey();
    if (!site) return;
    this.service.live(site).pipe(catchError(e => this.fail(e, [] as LiveVisitor[]))).subscribe(v => this.live.set(v));
  }

  copy(): void {
    const text = this.snippet();
    if (!text) return;
    const clipboard = globalThis.navigator?.clipboard;
    if (!clipboard) return;
    clipboard.writeText(text).then(
      () => this.copied.set(true),
      () => this.copied.set(false),
    );
  }

  protected time(iso: string): string {
    const at = new Date(iso);
    return Number.isNaN(at.getTime()) ? '' : new Intl.DateTimeFormat(this.lang.intlLocale(), { timeStyle: 'short' }).format(at);
  }

  private loadReport(): void {
    const site = this.siteKey();
    if (!site) return;
    this.service.report(site, this.days())
      .pipe(catchError(e => this.fail(e, null)))
      .subscribe(r => this.report.set(r));
  }

  private fail<T>(e: unknown, fallback: T) {
    this.error.set(this.lang.errorText(e as ApiError) || this.lang.translate('marketingTracking.loadFailed'));
    return of(fallback);
  }
}
