import { ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, signal, untracked } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  AnswerGroup, REPORT_BUCKETS, REPORT_FUNCS, REPORT_LAYOUTS, REPORT_OPERATORS, ReportBucket, ReportCondition, ReportFunc,
  ReportGroup, ReportLayout, ReportOperator, ReportState, emptyReport, pivot, ready, reportSpec, summarise, tableColumns,
} from './report-builder.model';

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
 */
@Component({
  selector: 'xrm-report-builder',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
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

  readonly spec = computed(() => reportSpec(this.state()));
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

  constructor() {
    // The live preview: each change waits a moment, then runs once.
    effect(onCleanup => {
      const spec = this.spec();
      if (!this.live() || !this.canRun()) return;
      const timer = setTimeout(() => untracked(() => this.run(spec)), PREVIEW_DELAY_MS);
      onCleanup(() => clearTimeout(timer));
    });
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
    this.api.post<RunAnswer>('/api/v1/query/run', { spec })
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

  private clearAnswer(): void {
    this.rows.set(null);
    this.groups.set(null);
    this.runError.set(null);
  }
}
