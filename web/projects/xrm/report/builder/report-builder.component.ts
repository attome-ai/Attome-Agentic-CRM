import { ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, signal, untracked } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { DashboardChartComponent, SLICE_COLORS } from '@attome/xrm/dashboard/chart';
import {
  AnswerGroup, PROMPT_TYPES, REPORT_BUCKETS, REPORT_CHARTS, REPORT_FUNCS, REPORT_LAYOUTS, REPORT_OPERATORS, ReportBucket,
  ReportChart, ReportCondition, ReportFunc, ReportGroup, ReportLayout, ReportOperator, ReportPrompt, ReportState, emptyReport,
  parameterDecls, pivot, promptNameOk, promptValues, ready, reportSpec, summarise, tableColumns,
} from './report-builder.model';
import { matrixChart, summaryChart } from './report-chart';

/** A role or team a saved report can be shared with. */
export interface SharePrincipal {
  type: 'role' | 'team';
  id: string;
  name: string;
}

/** One field of the entity, as `GET /api/v1/schema/{entity}` answers it. */
export interface ReportField {
  name: string;
  display_name: string;
  field_type: string;
}

/** `POST /api/v1/query/run`: rows, or aggregate groups. */
interface RunAnswer {
  items?: Record<string, unknown>[];
  groups?: AnswerGroup[];
}

/** Each layout's catalog key. */
const LAYOUT_KEYS: Record<ReportLayout, string> = {
  table: 'reportBuilder.layouts.table', summary: 'reportBuilder.layouts.summary', matrix: 'reportBuilder.layouts.matrix',
};
const FUNC_KEYS: Record<ReportFunc, string> = {
  count: 'reportBuilder.funcs.count', sum: 'reportBuilder.funcs.sum', avg: 'reportBuilder.funcs.avg',
  min: 'reportBuilder.funcs.min', max: 'reportBuilder.funcs.max',
};
const BUCKET_KEYS: Record<ReportBucket, string> = {
  day: 'reportBuilder.buckets.day', week: 'reportBuilder.buckets.week', month: 'reportBuilder.buckets.month',
  quarter: 'reportBuilder.buckets.quarter', year: 'reportBuilder.buckets.year',
};
const CHART_KEYS: Record<ReportChart, string> = {
  bar: 'reportBuilder.charts.bar', line: 'reportBuilder.charts.line', area: 'reportBuilder.charts.area',
  donut: 'reportBuilder.charts.donut', funnel: 'reportBuilder.charts.funnel',
};
const PROMPT_TYPE_KEYS = {
  text: 'reportBuilder.promptTypes.text', number: 'reportBuilder.promptTypes.number', date: 'reportBuilder.promptTypes.date',
} as const;

const OPERATOR_KEYS: Record<ReportOperator, string> = {
  eq: 'reportBuilder.ops.eq', neq: 'reportBuilder.ops.neq', gt: 'reportBuilder.ops.gt', gte: 'reportBuilder.ops.gte',
  lt: 'reportBuilder.ops.lt', lte: 'reportBuilder.ops.lte', contains: 'reportBuilder.ops.contains',
  is_null: 'reportBuilder.ops.is_null', is_not_null: 'reportBuilder.ops.is_not_null',
};

/** Milliseconds a change waits before the preview runs again. */
const PREVIEW_DELAY_MS = 400;

/**
 * P1-T1: a report built by pointing, not SQL. Pick an entity, then a layout:
 * a **table** of chosen columns (related fields by path, `account.industry`),
 * a **summary** of one measure (a count, or a sum, average, lowest or
 * highest of a field) grouped by a field (a date by day, week, month,
 * quarter or year) with its total, or a **matrix** of that measure by two
 * groupings with totals each way. Filters narrow it. The first 50 rows
 * preview live as the report changes, through `POST /api/v1/query/run`
 * under the person's own access; the totals are the server's (P1-T2), true
 * for every measure.
 *
 * P1-T3: a grouped report draws as a chart (bar, line, area, donut,
 * funnel); prompts ask for values at run time as the saved query's typed
 * parameters; a saved report (a stored query holding the spec) is shared
 * with roles and teams, to run or to edit, and a share never widens what
 * a person sees, because the spec runs with their own security.
 */
@Component({
  selector: 'xrm-report-builder',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DashboardChartComponent, TranslatePipe],
  templateUrl: './report-builder.component.html',
  styleUrl: './report-builder.component.css',
})
export class ReportBuilderComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly layouts = REPORT_LAYOUTS;
  readonly funcs = REPORT_FUNCS;
  readonly buckets = REPORT_BUCKETS;
  readonly operators = REPORT_OPERATORS;
  readonly layoutKeys = LAYOUT_KEYS;
  readonly funcKeys = FUNC_KEYS;
  readonly bucketKeys = BUCKET_KEYS;
  readonly operatorKeys = OPERATOR_KEYS;
  readonly charts = REPORT_CHARTS;
  readonly chartKeys = CHART_KEYS;
  readonly promptTypes = PROMPT_TYPES;
  readonly promptTypeKeys = PROMPT_TYPE_KEYS;
  readonly nameOk = promptNameOk;

  readonly entityInput = signal('');
  readonly relatedPath = signal('');
  readonly state = signal<ReportState>(emptyReport());
  readonly fields = signal<ReportField[]>([]);
  readonly schemaError = signal<string | null>(null);
  readonly running = signal(false);
  readonly runError = signal<string | null>(null);
  readonly rows = signal<Record<string, unknown>[] | null>(null);
  readonly groups = signal<AnswerGroup[] | null>(null);
  /** When false the preview waits for Preview to be pressed (tests, slow queries). */
  readonly live = signal(true);
  readonly chartKind = signal<ReportChart | ''>('');
  readonly reportName = signal('');
  readonly savedId = signal<string | null>(null);
  readonly principals = signal<SharePrincipal[]>([]);
  readonly shared = signal<Record<string, 'read' | 'edit'>>({});
  readonly shareNotice = signal<string | null>(null);

  readonly spec = computed(() => reportSpec(this.state()));
  readonly params = computed(() => promptValues(this.state().prompts));
  readonly canRun = computed(() => ready(this.state()));
  readonly dateFields = computed(() =>
    new Set(this.fields().filter(f => f.field_type === 'date' || f.field_type === 'date_time').map(f => f.name)));
  readonly numberFields = computed(() =>
    this.fields().filter(f => ['number', 'decimal', 'integer', 'currency', 'money', 'percent'].includes(f.field_type)));
  readonly columns = computed(() => tableColumns(this.state(), this.rows() ?? []));
  readonly summary = computed(() => {
    const g = this.groups();
    const s = this.state();
    return g && s.layout === 'summary' ? summarise(g, s.rows.field) : null;
  });
  readonly matrix = computed(() => {
    const g = this.groups();
    const s = this.state();
    return g && s.layout === 'matrix' ? pivot(g, s.rows.field, s.across.field) : null;
  });
  readonly chart = computed(() => {
    if (!this.chartKind()) return null;
    const s = this.summary();
    if (s) return summaryChart(s.lines, this.lang.translate(FUNC_KEYS[this.state().func]), SLICE_COLORS[0]);
    const m = this.matrix();
    return m ? matrixChart(m, SLICE_COLORS) : null;
  });

  constructor() {
    // The live preview: each change waits a moment, then runs once.
    effect(onCleanup => {
      const spec = this.spec();
      this.params();
      if (!this.live() || !this.canRun()) return;
      const timer = setTimeout(() => untracked(() => this.run(spec)), PREVIEW_DELAY_MS);
      onCleanup(() => clearTimeout(timer));
    });
    this.loadPrincipals();
  }

  label(name: string): string {
    return this.fields().find(f => f.name === name)?.display_name || name;
  }

  loadEntity(): void {
    const entity = this.entityInput().trim();
    if (!entity) return;
    this.schemaError.set(null);
    this.api.get<{ fields?: ReportField[] }>(`/api/v1/schema/${encodeURIComponent(entity)}`)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: schema => {
          this.fields.set(schema.fields ?? []);
          if (this.state().entity !== entity) this.state.set(emptyReport(entity));
          this.clearAnswer();
        },
        error: (e: ApiError) => {
          this.fields.set([]);
          this.schemaError.set(this.lang.errorText(e));
        },
      });
  }

  update(change: Partial<ReportState>): void {
    this.state.update(s => ({ ...s, ...change }));
  }

  setLayout(layout: ReportLayout): void {
    this.update({ layout });
    this.clearAnswer();
  }

  setGroup(which: 'rows' | 'across', change: Partial<ReportGroup>): void {
    const next = { ...this.state()[which], ...change };
    if (change.field !== undefined && !this.dateFields().has(next.field)) next.bucket = '';
    this.update({ [which]: next } as Partial<ReportState>);
  }

  toggleColumn(name: string): void {
    const columns = this.state().columns;
    this.update({ columns: columns.includes(name) ? columns.filter(c => c !== name) : [...columns, name] });
  }

  addRelated(): void {
    const path = this.relatedPath().trim();
    if (!/^[a-z0-9_]+(\.[a-z0-9_]+)+$/.test(path) || this.state().columns.includes(path)) return;
    this.update({ columns: [...this.state().columns, path] });
    this.relatedPath.set('');
  }

  addCondition(): void {
    this.update({ conditions: [...this.state().conditions, { field: '', op: 'eq', value: '' }] });
  }

  setCondition(index: number, change: Partial<ReportCondition>): void {
    this.update({ conditions: this.state().conditions.map((c, i) => (i === index ? { ...c, ...change } : c)) });
  }

  removeCondition(index: number): void {
    this.update({ conditions: this.state().conditions.filter((_, i) => i !== index) });
  }

  addPrompt(): void {
    const n = this.state().prompts.length + 1;
    this.update({ prompts: [...this.state().prompts, { field: '', op: 'eq', name: `value_${n}`, type: 'text', value: '' }] });
  }

  setPrompt(index: number, change: Partial<ReportPrompt>): void {
    this.update({ prompts: this.state().prompts.map((p, i) => (i === index ? { ...p, ...change } : p)) });
  }

  removePrompt(index: number): void {
    this.update({ prompts: this.state().prompts.filter((_, i) => i !== index) });
  }

  pickPromptType(index: number, event: Event): void {
    const value = this.valueOf(event);
    const type = PROMPT_TYPES.find(t => t === value);
    if (type) this.setPrompt(index, { type });
  }

  pickPromptOperator(index: number, event: Event): void {
    const value = this.valueOf(event);
    const op = REPORT_OPERATORS.find(o => o === value);
    if (op) this.setPrompt(index, { op });
  }

  pickChart(event: Event): void {
    const value = this.valueOf(event);
    this.chartKind.set(REPORT_CHARTS.find(c => c === value) ?? '');
  }

  /** Saves the report as a stored query holding its spec and its prompts' parameters. */
  saveReport(): void {
    const name = this.reportName().trim();
    if (!name || !this.canRun()) return;
    this.running.set(true);
    this.runError.set(null);
    this.api.post<{ id: string }>('/api/v1/admin/queries', {
      name, query_spec: this.spec(), parameters: parameterDecls(this.state().prompts),
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: saved => {
        this.running.set(false);
        this.savedId.set(saved.id);
      },
      error: (e: ApiError) => {
        this.running.set(false);
        this.runError.set(this.lang.errorText(e));
      },
    });
  }

  /** Shares (or stops sharing) the saved report with `p`; `edit` lets them change it too. */
  setShare(p: SharePrincipal, access: 'none' | 'read' | 'edit'): void {
    this.shared.update(all => {
      const next = { ...all };
      if (access === 'none') delete next[`${p.type}:${p.id}`];
      else next[`${p.type}:${p.id}`] = access;
      return next;
    });
  }

  pickShare(p: SharePrincipal, event: Event): void {
    const value = this.valueOf(event);
    this.setShare(p, value === 'read' || value === 'edit' ? value : 'none');
  }

  applyShares(): void {
    const id = this.savedId();
    if (!id) return;
    const shares = Object.entries(this.shared()).map(([key, access]) => {
      const [principal_type, principal_id] = key.split(':');
      return { principal_type, principal_id, access };
    });
    this.api.put(`/api/v1/admin/query-shares/${encodeURIComponent(id)}`, { shares })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.shareNotice.set(this.lang.translate('reportBuilder.shareSaved', { count: shares.length })),
        error: (e: ApiError) => this.runError.set(this.lang.errorText(e)),
      });
  }

  // Template event readers: the value of the control that fired.
  valueOf(event: Event): string {
    return (event.target as HTMLInputElement | HTMLSelectElement).value;
  }

  pickFunc(event: Event): void {
    const value = this.valueOf(event);
    const func = REPORT_FUNCS.find(f => f === value);
    if (func) this.update({ func, field: func === 'count' ? '' : this.state().field });
  }

  pickBucket(which: 'rows' | 'across', event: Event): void {
    const value = this.valueOf(event);
    this.setGroup(which, { bucket: REPORT_BUCKETS.find(b => b === value) ?? '' });
  }

  pickOperator(index: number, event: Event): void {
    const value = this.valueOf(event);
    const op = REPORT_OPERATORS.find(o => o === value);
    if (op) this.setCondition(index, { op });
  }

  /** Runs the report's spec (the current one when none is given) for the preview. */
  run(spec: Record<string, unknown> = this.spec()): void {
    if (!this.canRun()) return;
    this.running.set(true);
    this.runError.set(null);
    const params = this.params();
    const body: Record<string, unknown> = Object.keys(params).length ? { spec, params } : { spec };
    this.api.post<RunAnswer>('/api/v1/query/run', body)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: answer => {
          this.running.set(false);
          this.rows.set(answer.items ?? null);
          this.groups.set(answer.groups ?? null);
        },
        error: (e: ApiError) => {
          this.running.set(false);
          this.runError.set(this.lang.errorText(e));
        },
      });
  }

  private loadPrincipals(): void {
    for (const type of ['role', 'team'] as const) {
      this.api.get<{ items?: Record<string, unknown>[] }>(`/api/v1/${type}`, { page_size: '200', sort: 'name' })
        .pipe(takeUntilDestroyed(this.destroyRef))
        .subscribe({
          next: page => this.principals.update(all => [
            ...all.filter(p => p.type !== type),
            ...(page.items ?? []).map(r => {
              const data = (r['data'] ?? r) as Record<string, unknown>;
              return { type, id: String(r['id']), name: typeof data['name'] === 'string' ? data['name'] : String(r['id']) };
            }),
          ]),
          // Without access to the list, sharing offers nobody.
          error: () => undefined,
        });
    }
  }

  private clearAnswer(): void {
    this.rows.set(null);
    this.groups.set(null);
    this.runError.set(null);
  }
}
