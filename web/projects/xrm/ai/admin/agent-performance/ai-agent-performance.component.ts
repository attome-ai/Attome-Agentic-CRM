import { NgComponentOutlet } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ChartCategory, ChartSeries } from '@attome/xrm/dashboard/chart';

import {
  AgentBehaviour,
  AgentPerformance,
  AgentPerformanceDay,
  AgentRun,
  AiAgentPerformanceService,
  RunsMetric,
} from './ai-agent-performance.service';

type ChartModule = typeof import('@attome/xrm/dashboard/chart');

/** `YYYY-MM-DD` of a date (UTC). Pure. */
export function isoDay(date: Date): string {
  return date.toISOString().slice(0, 10);
}

/** The last 30 days ending yesterday: the rollup's freshest complete day. Pure. */
export function defaultRange(now: Date = new Date()): { from: string; to: string } {
  const to = new Date(now.getTime() - 86_400_000);
  const from = new Date(to.getTime() - 29 * 86_400_000);
  return { from: isoDay(from), to: isoDay(to) };
}

/** A cost in millionths as an amount, or `null` when no price is set. Pure. */
export function costAmount(micros: number | null, unit: string | null): number | null {
  if (unit === null || micros === null) return null;
  return micros / 1_000_000;
}

/** The trend chart's categories and series (tasks done, resolved), colours left to the caller. Pure. */
export function trend(days: AgentPerformanceDay[], names: { done: string; resolved: string }): {
  categories: ChartCategory[];
  series: Omit<ChartSeries, 'color'>[];
} {
  const categories = days.map(d => ({ trackKey: d.day, label: d.day }));
  const point = (d: AgentPerformanceDay, value: number, key: string) => ({
    trackKey: `${key}:${d.day}`, label: d.day, value, key: null,
  });
  return {
    categories,
    series: [
      { trackKey: 'done', name: names.done, points: days.map(d => point(d, d.tasks_done, 'done')) },
      { trackKey: 'resolved', name: names.resolved, points: days.map(d => point(d, d.tasks_resolved, 'resolved')) },
    ],
  };
}

/**
 * AI8-T6: how each agent is doing over a range, from the nightly rollup.
 * The table shows tasks, resolution, accuracy, hand-off rate, estimated time
 * saved, tokens and cost per task (or "no price set" when some tokens had no
 * price — never a misleading 0). Choosing an agent shows its daily trend
 * (the dashboard's chart, loaded on its own) and its days; every number of a
 * day opens the runs behind it. Numbers follow the page's locale, Arabic
 * digits included; logical CSS only.
 */
@Component({
  selector: 'xrm-ai-agent-performance',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, NgComponentOutlet, RouterLink, TranslatePipe],
  template: `
    <section class="aap">
      <h2>{{ 'aiPerformance.title' | translate }}</h2>
      <p class="aap-muted">{{ 'aiPerformance.intro' | translate }}</p>
      <a class="aap-link" routerLink="/xrm/ai/agents/work-share">{{ 'aiWorkShare.link' | translate }}</a>
      <form class="aap-range" (ngSubmit)="load()">
        <label>{{ 'aiPerformance.from' | translate }} <input type="date" name="from" [(ngModel)]="from" /></label>
        <label>{{ 'aiPerformance.to' | translate }} <input type="date" name="to" [(ngModel)]="to" /></label>
        <button type="submit">{{ 'aiPerformance.show' | translate }}</button>
      </form>
      @if (error(); as message) { <p class="aap-error" role="alert">{{ message }}</p> }

      <div class="aap-scroll">
        <table class="aap-table">
          <thead>
            <tr>
              <th scope="col">{{ 'aiPerformance.agent' | translate }}</th>
              <th scope="col">{{ 'aiPerformance.tasks' | translate }}</th>
              <th scope="col">{{ 'aiPerformance.resolution' | translate }}</th>
              <th scope="col">{{ 'aiPerformance.accuracy' | translate }}</th>
              <th scope="col">{{ 'aiPerformance.handoffRate' | translate }}</th>
              <th scope="col">{{ 'aiPerformance.timeSaved' | translate }}</th>
              <th scope="col">{{ 'aiPerformance.tokens' | translate }}</th>
              <th scope="col">{{ 'aiPerformance.costPerTask' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (a of agents(); track a.agent_id) {
              <tr [attr.data-agent]="a.agent_id" [class.aap-selected]="selected()?.agent_id === a.agent_id">
                <th scope="row"><button type="button" class="aap-link" (click)="select(a)">{{ a.name || a.agent_id }}</button></th>
                <td><button type="button" class="aap-link" (click)="select(a)">{{ num(a.tasks_done) }}</button></td>
                <td>{{ pct(a.resolution_rate) }}</td>
                <td>{{ pct(a.accuracy) }}</td>
                <td>{{ pct(a.handoff_rate) }}</td>
                <td>{{ hours(a.time_saved_seconds) }}</td>
                <td>{{ num(a.input_tokens + a.output_tokens) }}</td>
                <td>
                  @if (a.cost_unit !== null && a.cost_per_task_micros !== null) {
                    {{ money(cost(a.cost_per_task_micros, a.cost_unit) ?? 0) }}
                  } @else {
                    <span class="aap-muted" data-no-price>{{ 'aiPerformance.noPrice' | translate }}</span>
                  }
                </td>
              </tr>
            } @empty {
              <tr><td colspan="8" class="aap-muted">{{ 'aiPerformance.none' | translate }}</td></tr>
            }
          </tbody>
        </table>
      </div>
      <p class="aap-muted">{{ 'aiPerformance.estimate' | translate }}</p>

      @if (selected(); as agent) {
        <h3>{{ agent.name || agent.agent_id }}</h3>
        @if (behaviour(); as b) {
          <section class="aap-behaviour" data-testid="behaviour" [attr.aria-label]="'aiPerformance.behaviour.title' | translate">
            <h4>{{ 'aiPerformance.behaviour.title' | translate }}</h4>
            @if (b.status === 'suspended') {
              <p class="aap-stopped" role="status" data-testid="trip">
                <strong>{{ 'aiPerformance.behaviour.stopped' | translate }}</strong>
                @if (b.last_trip; as trip) {
                  · {{ trip.at | localDate: { dateStyle: 'short', timeStyle: 'short' } }}
                  · <span dir="ltr" data-testid="trip-reason">{{ trip.reason }}</span>
                }
              </p>
              <button type="button" data-testid="switch-on" [disabled]="switching()" (click)="switchOn(b)">
                {{ 'aiPerformance.behaviour.switchOn' | translate }}
              </button>
            }
            @if (b.baseline; as base) {
              <p class="aap-muted">
                {{ 'aiPerformance.behaviour.usual' | translate: {
                  mean: num(round1(base.mean_writes_per_hour)), spread: num(round1(base.stddev_writes_per_hour)) } }}
              </p>
            } @else {
              <p class="aap-muted">{{ 'aiPerformance.behaviour.learning' | translate }}</p>
            }
            @if (chartModule(); as m) {
              @if (hourInputs(); as inputs) {
                <ng-container *ngComponentOutlet="m.DashboardChartComponent; inputs: inputs" />
              }
            }
          </section>
        }
        @if (chartModule(); as m) {
          @if (chartInputs(); as inputs) {
            <ng-container *ngComponentOutlet="m.DashboardChartComponent; inputs: inputs" />
          }
        }
        <div class="aap-scroll">
          <table class="aap-table">
            <thead>
              <tr>
                <th scope="col">{{ 'aiPerformance.day' | translate }}</th>
                <th scope="col">{{ 'aiPerformance.tasks' | translate }}</th>
                <th scope="col">{{ 'aiPerformance.handoffs' | translate }}</th>
                <th scope="col">{{ 'aiPerformance.cost' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (d of days(); track d.day) {
                <tr [attr.data-day]="d.day">
                  <th scope="row">{{ d.day | localDate }}</th>
                  <td><button type="button" class="aap-link" (click)="openRuns(d.day, 'tasks')">{{ num(d.tasks_done) }}</button></td>
                  <td><button type="button" class="aap-link" (click)="openRuns(d.day, 'handoffs')">{{ num(d.handoffs) }}</button></td>
                  <td>
                    <button type="button" class="aap-link" (click)="openRuns(d.day, 'cost')">
                      @if (d.cost_unit !== null) { {{ money(cost(d.cost_micros, d.cost_unit) ?? 0) }} } @else { {{ 'aiPerformance.noPrice' | translate }} }
                    </button>
                  </td>
                </tr>
              }
            </tbody>
          </table>
        </div>
      }

      @if (runsFor(); as r) {
        <aside class="aap-runs" role="dialog" [attr.aria-label]="'aiPerformance.runs' | translate">
          <header class="aap-runs-head">
            <h3>{{ 'aiPerformance.runs' | translate }} · {{ r.day | localDate }}</h3>
            <button type="button" (click)="closeRuns()">{{ 'aiPerformance.close' | translate }}</button>
          </header>
          <ul>
            @for (run of runs(); track run.id) {
              <li [attr.data-run]="run.id">
                <small>{{ run.at | localDate: { dateStyle: 'short', timeStyle: 'short' } }}</small>
                @if (run.source) { <span>{{ 'aiPerformance.source.' + run.source | translate }}</span> }
                @if (run.regarding_entity) { <code>{{ run.regarding_entity }}</code> }
                @if (run.input_tokens !== null) { <span>{{ num((run.input_tokens ?? 0) + (run.output_tokens ?? 0)) }} {{ 'aiPerformance.tokens' | translate }}</span> }
              </li>
            } @empty {
              <li class="aap-muted">{{ 'aiPerformance.noRuns' | translate }}</li>
            }
          </ul>
          @if (nextCursor()) {
            <button type="button" (click)="moreRuns()">{{ 'aiPerformance.more' | translate }}</button>
          }
        </aside>
      }
    </section>
  `,
  styles: [`
    :host { display: block; padding-block: 1rem; padding-inline: 1rem; }
    .aap { display: flex; flex-direction: column; gap: 0.75rem; max-inline-size: 72rem; }
    .aap h2 { margin-block: 0; font-size: 1.125rem; }
    .aap h3 { margin-block: 0.5rem 0; font-size: 1rem; }
    .aap-range { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: end; }
    .aap-range label { display: flex; flex-direction: column; gap: 0.25rem; }
    .aap-scroll { overflow-x: auto; }
    .aap-table { border-collapse: collapse; inline-size: 100%; }
    .aap-table th, .aap-table td { padding-block: 0.375rem; padding-inline: 0.5rem; text-align: start;
      border-block-end: 1px solid var(--color-border); white-space: nowrap; }
    .aap-selected { background: var(--color-bg-alt); }
    .aap-link { background: none; border: none; padding: 0; color: var(--color-primary); cursor: pointer; font: inherit; }
    .aap-runs { border: 1px solid var(--color-border); border-radius: 0.5rem; padding-block: 0.75rem; padding-inline: 0.75rem; }
    .aap-runs-head { display: flex; align-items: center; gap: 0.75rem; }
    .aap-runs-head h3 { flex: 1 1 auto; margin-block: 0; }
    .aap-runs ul { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.375rem; }
    .aap-runs li { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: baseline; }
    .aap-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .aap-error { color: var(--color-danger); }
    .aap-behaviour { border: 1px solid var(--color-border); border-radius: 0.5rem; padding-block: 0.75rem;
      padding-inline: 0.75rem; display: flex; flex-direction: column; gap: 0.5rem; }
    .aap-behaviour h4 { margin-block: 0; font-size: 0.9375rem; }
    .aap-stopped { margin-block: 0; }
  `],
})
export class AiAgentPerformanceComponent implements OnInit {
  private readonly performance = inject(AiAgentPerformanceService);
  private readonly lang = inject(LangService);

  from = defaultRange().from;
  to = defaultRange().to;

  readonly agents = signal<AgentPerformance[]>([]);
  readonly selected = signal<AgentPerformance | null>(null);
  readonly days = signal<AgentPerformanceDay[]>([]);
  readonly runsFor = signal<{ day: string; metric: RunsMetric } | null>(null);
  readonly runs = signal<AgentRun[]>([]);
  readonly nextCursor = signal<string | null>(null);
  readonly error = signal<string | null>(null);
  readonly chartModule = signal<ChartModule | null>(null);
  /** AH5-T5: the chosen agent's behaviour, and a switch-on in flight. */
  readonly behaviour = signal<AgentBehaviour | null>(null);
  readonly switching = signal(false);

  /** The last 24 hours' writes as bars. */
  readonly hourInputs = computed(() => {
    const m = this.chartModule();
    const hours = this.behaviour()?.hours ?? [];
    if (!m || hours.length === 0) return null;
    const label = (h: string) => h.slice(11, 16);
    return {
      kind: 'bar',
      title: this.lang.translate('aiPerformance.behaviour.hours'),
      categories: hours.map(h => ({ trackKey: h.hour, label: label(h.hour) })),
      series: [{
        trackKey: 'writes',
        name: this.lang.translate('aiPerformance.behaviour.writes'),
        color: m.SLICE_COLORS[0],
        points: hours.map(h => ({ trackKey: `writes:${h.hour}`, label: label(h.hour), value: h.writes, key: null })),
      }],
    };
  });

  readonly chartInputs = computed(() => {
    const m = this.chartModule();
    const days = this.days();
    if (!m || days.length === 0) return null;
    const t = trend(days, {
      done: this.lang.translate('aiPerformance.tasks'),
      resolved: this.lang.translate('aiPerformance.resolved'),
    });
    return {
      kind: 'line',
      title: this.lang.translate('aiPerformance.trend'),
      categories: t.categories,
      series: t.series.map((s, i) => ({ ...s, color: m.SLICE_COLORS[i % m.SLICE_COLORS.length] })),
    };
  });

  readonly cost = costAmount;

  ngOnInit(): void {
    this.load();
    import('@attome/xrm/dashboard/chart').then(
      m => this.chartModule.set(m),
      () => this.chartModule.set(null),
    );
  }

  private fail(e: ApiError): void {
    this.error.set(this.lang.errorText(e));
  }

  num(value: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale()).format(value);
  }

  pct(value: number | null): string {
    if (value === null) return '—';
    return new Intl.NumberFormat(this.lang.intlLocale(), { style: 'percent', maximumFractionDigits: 0 }).format(value);
  }

  money(amount: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale(), { maximumFractionDigits: 4 }).format(amount);
  }

  hours(seconds: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale(), {
      style: 'unit', unit: 'hour', maximumFractionDigits: 1,
    }).format(seconds / 3600);
  }

  load(): void {
    this.error.set(null);
    this.performance.summary(this.from, this.to).subscribe({
      next: page => {
        this.agents.set(page.items);
        const kept = this.selected();
        if (kept) {
          const again = page.items.find(a => a.agent_id === kept.agent_id) ?? null;
          this.selected.set(again);
          if (again) this.loadDays(again.agent_id);
        }
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  select(agent: AgentPerformance): void {
    this.selected.set(agent);
    this.closeRuns();
    this.loadDays(agent.agent_id);
    this.loadBehaviour(agent.agent_id);
  }

  round1(value: number | null): number {
    return Math.round((value ?? 0) * 10) / 10;
  }

  private loadBehaviour(agentId: string): void {
    this.behaviour.set(null);
    this.performance.behaviour(agentId).subscribe({
      next: b => this.behaviour.set(b),
      error: () => this.behaviour.set(null),
    });
  }

  /** A person switches a stopped agent back on. */
  switchOn(b: AgentBehaviour): void {
    if (this.switching()) return;
    this.switching.set(true);
    this.performance.switchOn(b.agent_id, b.row_version).subscribe({
      next: () => { this.switching.set(false); this.loadBehaviour(b.agent_id); },
      error: (e: ApiError) => { this.switching.set(false); this.fail(e); },
    });
  }

  private loadDays(agentId: string): void {
    this.performance.daily(agentId, this.from, this.to).subscribe({
      next: page => this.days.set(page.items),
      error: (e: ApiError) => this.fail(e),
    });
  }

  openRuns(day: string, metric: RunsMetric): void {
    const agent = this.selected();
    if (!agent) return;
    this.runsFor.set({ day, metric });
    this.runs.set([]);
    this.nextCursor.set(null);
    this.performance.runs(agent.agent_id, day, metric).subscribe({
      next: page => { this.runs.set(page.items); this.nextCursor.set(page.next_cursor); },
      error: (e: ApiError) => this.fail(e),
    });
  }

  moreRuns(): void {
    const agent = this.selected();
    const target = this.runsFor();
    const cursor = this.nextCursor();
    if (!agent || !target || !cursor) return;
    this.performance.runs(agent.agent_id, target.day, target.metric, cursor).subscribe({
      next: page => { this.runs.update(r => [...r, ...page.items]); this.nextCursor.set(page.next_cursor); },
      error: (e: ApiError) => this.fail(e),
    });
  }

  closeRuns(): void {
    this.runsFor.set(null);
    this.runs.set([]);
    this.nextCursor.set(null);
  }
}
