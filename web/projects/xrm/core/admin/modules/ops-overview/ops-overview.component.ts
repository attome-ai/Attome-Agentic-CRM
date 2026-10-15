import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

import { MetricInfo, MetricPoint, polyline } from '../metrics/metrics.component';

/** `system_health::OpsNode`. */
export interface OpsNode {
  node: string;
  version: string | null;
  last_seen: string;
  healthy: boolean;
}

/** The dashboard pages, in order. */
export const AREAS = ['requests', 'database', 'cache', 'jobs', 'storage', 'email', 'models', 'other'] as const;
export type Area = typeof AREAS[number];

/** Which page a metric belongs on, from its name. */
export function areaOf(name: string): Area {
  const n = name.toLowerCase();
  const has = (...parts: string[]) => parts.some(p => n.includes(p));
  if (has('ai_', 'inference', 'model', 'llm', 'embedding')) return 'models';
  if (has('http', 'request', 'latency', 'route')) return 'requests';
  if (has('db_', 'pg_', 'pool', 'sqlx', 'database')) return 'database';
  if (has('cache', 'redis', 'dragonfly')) return 'cache';
  if (has('apalis', 'job', 'worker', 'queue')) return 'jobs';
  if (has('storage', 's3', 'object', 'upload', 'file')) return 'storage';
  if (has('email', 'smtp', 'mail')) return 'email';
  return 'other';
}

/** Charts one page draws at most. */
const MAX_CHARTS = 24;
const WIDTH = 240;
const HEIGHT = 48;

interface Chart {
  info: MetricInfo;
  line: string;
  last: number | null;
}

/**
 * Operations overview (roadmap U4-T4): the nodes, coloured by health, and one
 * page per area (requests, database, cache, jobs, storage, email, models)
 * with the last hour of each sampled metric, all from the built-in metrics
 * store, so no Prometheus is needed. Logical CSS only; charts are plain SVG.
 */
@Component({
  selector: 'xrm-ops-overview',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="oo">
      <h2>{{ 'opsOverview.title' | translate }}</h2>
      @if (error(); as message) { <p class="oo-error" role="alert">{{ message }}</p> }

      <h3>{{ 'opsOverview.nodes' | translate }}</h3>
      @if (nodes().length === 0) {
        <p class="oo-muted">{{ 'opsOverview.noNodes' | translate }}</p>
      } @else {
        <ul class="oo-nodes" data-nodes>
          @for (n of nodes(); track n.node) {
            <li class="oo-node" [class.oo-down]="!n.healthy" [attr.data-node]="n.node">
              <span class="oo-dot" aria-hidden="true"></span>
              <span dir="ltr" class="oo-name">{{ n.node }}</span>
              <span class="oo-muted">{{ (n.healthy ? 'opsOverview.healthy' : 'opsOverview.silent') | translate }}</span>
              <span class="oo-muted" dir="ltr">{{ n.version ?? '' }}</span>
              <span class="oo-muted">{{ n.last_seen | localDate }}</span>
            </li>
          }
        </ul>
      }

      <div class="oo-tabs" role="tablist">
        @for (a of areas; track a) {
          <button type="button" role="tab" class="btn btn-text" [class.oo-on]="a === area()"
                  [attr.aria-selected]="a === area()" (click)="choose(a)" [attr.data-area]="a">
            {{ 'opsOverview.area.' + a | translate }}
          </button>
        }
      </div>
      @if (charts().length === 0) {
        <p class="oo-muted">{{ 'opsOverview.noMetrics' | translate }}</p>
      }
      <div class="oo-grid">
        @for (c of charts(); track c.info.name) {
          <figure class="oo-card" [attr.data-chart]="c.info.name">
            <figcaption>
              <span dir="ltr" class="oo-name">{{ c.info.name }}</span>
              <span class="oo-muted">{{ meaning(c.info) }}</span>
            </figcaption>
            <svg [attr.viewBox]="'0 0 ' + width + ' ' + height" role="img" [attr.aria-label]="c.info.name">
              <polyline [attr.points]="c.line" fill="none" stroke="var(--color-primary)" stroke-width="2" />
            </svg>
            <span dir="ltr" class="oo-last">{{ c.last === null ? '—' : format(c.last) }} {{ c.info.unit }}</span>
          </figure>
        }
      </div>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .oo { display: flex; flex-direction: column; gap: 0.75rem; }
    .oo h2 { margin-block: 0; font-size: 1.25rem; }
    .oo h3 { margin-block: 0; font-size: 1rem; }
    .oo-nodes { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 0.5rem; }
    .oo-node { display: flex; align-items: center; gap: 0.5rem; padding-block: 0.375rem; padding-inline: 0.75rem;
      border: 1px solid var(--color-border); border-radius: 999px; font-size: 0.875rem; }
    .oo-dot { inline-size: 0.625rem; block-size: 0.625rem; border-radius: 50%; background: var(--color-success); }
    .oo-down .oo-dot { background: var(--color-danger); }
    .oo-tabs { display: flex; flex-wrap: wrap; gap: 0.25rem; }
    .oo-on { font-weight: 600; text-decoration: underline; }
    .oo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(16rem, 1fr)); gap: 0.75rem; }
    .oo-card { margin: 0; padding: 0.5rem; border: 1px solid var(--color-border); border-radius: 6px;
      display: flex; flex-direction: column; gap: 0.25rem; }
    .oo-card figcaption { display: flex; flex-direction: column; font-size: 0.8125rem; }
    .oo-card svg { inline-size: 100%; block-size: auto; }
    .oo-name { font-weight: 600; overflow-wrap: anywhere; }
    .oo-last { font-size: 0.875rem; }
    .oo-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .oo-error { color: var(--color-danger); }
  `],
})
export class OpsOverviewComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly catalogue = signal<MetricInfo[]>([]);
  private readonly sampled = signal<Set<string>>(new Set());
  private readonly series = signal<Record<string, MetricPoint[]>>({});

  readonly areas = AREAS;
  readonly width = WIDTH;
  readonly height = HEIGHT;
  readonly area = signal<Area>('requests');
  readonly nodes = signal<OpsNode[]>([]);
  readonly error = signal<string | null>(null);

  /** The chosen page's sampled metrics, in catalogue order. */
  readonly metrics = computed(() => this.catalogue()
    .filter(m => this.sampled().has(m.name) && areaOf(m.name) === this.area())
    .slice(0, MAX_CHARTS));

  readonly charts = computed((): Chart[] => this.metrics().map(info => {
    const points = this.series()[info.name] ?? [];
    return {
      info,
      line: polyline(points, WIDTH, HEIGHT),
      last: points.length ? points[points.length - 1].value : null,
    };
  }));

  ngOnInit(): void {
    this.api.get<{ items: OpsNode[] }>('/api/v1/admin/ops/nodes').subscribe({
      next: page => this.nodes.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.api.get<{ items: MetricInfo[] }>('/api/v1/admin/ops/metrics/catalogue').subscribe({
      next: page => { this.catalogue.set(page.items); this.loadArea(); },
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.api.get<{ items: string[] }>('/api/v1/admin/ops/metrics/names').subscribe({
      next: page => { this.sampled.set(new Set(page.items)); this.loadArea(); },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  choose(area: Area): void {
    this.area.set(area);
    this.loadArea();
  }

  /** The metric's meaning in the interface language. */
  meaning(info: MetricInfo): string {
    return this.lang.current() === 'ar' ? info.ar : info.en;
  }

  format(value: number): string {
    return Number.isInteger(value) ? String(value) : value.toFixed(2);
  }

  /** Fetches the last hour of each chart on the page not fetched yet. */
  private loadArea(): void {
    const to = new Date();
    const from = new Date(to.getTime() - 3_600_000);
    for (const info of this.metrics()) {
      if (this.series()[info.name]) continue;
      this.series.update(s => ({ ...s, [info.name]: [] }));
      this.api.get<{ items: MetricPoint[] }>('/api/v1/admin/ops/metrics/query', {
        name: info.name, from: from.toISOString(), to: to.toISOString(), step: '60',
      }).subscribe({
        next: page => this.series.update(s => ({ ...s, [info.name]: page.items })),
        error: () => undefined,
      });
    }
  }
}
