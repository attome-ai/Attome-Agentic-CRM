import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  BUILDER_FUNCS, BUILDER_OPERATORS, BuilderState, DATE_BUCKETS, buildSpec, columnsOf, emptyState,
  stateFromFilter,
} from './query-builder.model';

/** One field of the entity, as `GET /api/v1/schema/{entity}` answers it. */
interface SchemaField {
  name: string;
  display_name: string;
  field_type: string;
}

interface SchemaAnswer {
  fields: SchemaField[];
}

/** `POST /api/v1/query/run`: rows with a cursor, or aggregate groups. */
interface RunAnswer {
  items?: Record<string, unknown>[];
  next_cursor?: string | null;
  groups?: { keys: Record<string, unknown>; values: Record<string, unknown> }[];
}

/** `search.parse_filter`'s outcome. */
interface ParseOutcome {
  status: string;
  result?: { status?: string; filter?: { entity: string; where?: unknown }; reason?: string };
}

/**
 * A14-T3: build a query by clicking or by a sentence. Pick the entity, its
 * columns (a related field by its path, `account.industry`, is a join),
 * conditions, a grouping (a date by day, week, month, quarter or year) with
 * summaries, and a sort; the builder makes the QuerySpec and runs it through
 * `POST /api/v1/query/run` under the person's own access. A sentence goes to
 * `search.parse_filter` (the model sees only what the person may read) and
 * comes back as a proposal: nothing changes until the person applies it.
 * The query can be saved as a stored query (`query_spec`).
 */
@Component({
  selector: 'xrm-query-builder',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../query-page.css', './query-builder.component.css'],
  templateUrl: './query-builder.component.html',
})
export class QueryBuilderComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly operators = BUILDER_OPERATORS;
  readonly funcs = BUILDER_FUNCS;
  readonly buckets = DATE_BUCKETS;

  readonly state = signal<BuilderState>(emptyState());
  readonly fields = signal<SchemaField[]>([]);
  readonly entityInput = signal('');
  readonly relatedPath = signal('');
  readonly schemaError = signal<string | null>(null);

  readonly sentence = signal('');
  readonly asking = signal(false);
  readonly proposal = signal<BuilderState | null>(null);
  readonly declined = signal(false);

  readonly running = signal(false);
  readonly runError = signal<string | null>(null);
  readonly rows = signal<Record<string, unknown>[] | null>(null);
  readonly groups = signal<{ keys: Record<string, unknown>; values: Record<string, unknown> }[] | null>(null);

  readonly saveName = signal('');
  readonly saved = signal(false);

  readonly spec = computed(() => buildSpec(this.state()));
  readonly columns = computed(() => columnsOf(this.rows() ?? []));
  readonly dateFields = computed(() =>
    new Set(this.fields().filter(f => f.field_type === 'date' || f.field_type === 'date_time').map(f => f.name)));
  readonly groupColumns = computed(() => {
    const first = this.groups()?.[0];
    return first ? [...Object.keys(first.keys), ...Object.keys(first.values)] : [];
  });

  /** Loads the entity's fields for the pickers. */
  loadEntity(): void {
    const entity = this.entityInput().trim();
    if (!entity) return;
    this.schemaError.set(null);
    this.api.get<SchemaAnswer>(`/api/v1/schema/${encodeURIComponent(entity)}`)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: schema => {
          this.fields.set(schema.fields ?? []);
          if (this.state().entity !== entity) this.state.set(emptyState(entity));
        },
        error: (e: ApiError) => {
          this.fields.set([]);
          this.schemaError.set(this.lang.errorText(e));
        },
      });
  }

  update(change: Partial<BuilderState>): void {
    this.state.update(s => ({ ...s, ...change }));
    this.saved.set(false);
  }

  toggleColumn(name: string): void {
    const select = this.state().select;
    this.update({ select: select.includes(name) ? select.filter(s => s !== name) : [...select, name] });
  }

  addRelated(): void {
    const path = this.relatedPath().trim();
    if (!path.includes('.') || this.state().select.includes(path)) return;
    this.update({ select: [...this.state().select, path] });
    this.relatedPath.set('');
  }

  addCondition(): void {
    this.update({ conditions: [...this.state().conditions, { field: '', op: 'eq', value: '' }] });
  }

  setCondition(index: number, change: Partial<BuilderState['conditions'][number]>): void {
    this.update({ conditions: this.state().conditions.map((c, i) => (i === index ? { ...c, ...change } : c)) });
  }

  removeCondition(index: number): void {
    this.update({ conditions: this.state().conditions.filter((_, i) => i !== index) });
  }

  addGroup(): void {
    this.update({ groups: [...this.state().groups, { field: '', bucket: '' }] });
  }

  setGroup(index: number, change: Partial<BuilderState['groups'][number]>): void {
    this.update({ groups: this.state().groups.map((g, i) => (i === index ? { ...g, ...change } : g)) });
  }

  removeGroup(index: number): void {
    this.update({ groups: this.state().groups.filter((_, i) => i !== index) });
  }

  addAggregate(): void {
    const n = this.state().aggregates.length + 1;
    this.update({ aggregates: [...this.state().aggregates, { func: 'count', field: '', alias: `value_${n}` }] });
  }

  setAggregate(index: number, change: Partial<BuilderState['aggregates'][number]>): void {
    this.update({ aggregates: this.state().aggregates.map((a, i) => (i === index ? { ...a, ...change } : a)) });
  }

  removeAggregate(index: number): void {
    this.update({ aggregates: this.state().aggregates.filter((_, i) => i !== index) });
  }

  /** Turns the sentence into a proposed query; nothing changes until applied. */
  ask(): void {
    const query = this.sentence().trim();
    if (!query) return;
    this.asking.set(true);
    this.declined.set(false);
    this.proposal.set(null);
    this.api.post<ParseOutcome>('/api/v1/actions/search.parse_filter/invoke', { args: { query } })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: outcome => {
          this.asking.set(false);
          const filter = outcome.status === 'completed' && outcome.result?.status === 'parsed'
            ? outcome.result.filter : undefined;
          if (filter?.entity) this.proposal.set(stateFromFilter(filter));
          else this.declined.set(true);
        },
        error: () => {
          this.asking.set(false);
          this.declined.set(true);
        },
      });
  }

  applyProposal(): void {
    const proposal = this.proposal();
    if (!proposal) return;
    this.state.set(proposal);
    this.entityInput.set(proposal.entity);
    this.proposal.set(null);
    this.loadEntity();
  }

  dismissProposal(): void {
    this.proposal.set(null);
  }

  run(): void {
    if (!this.state().entity) return;
    this.running.set(true);
    this.runError.set(null);
    this.api.post<RunAnswer>('/api/v1/query/run', { spec: this.spec() })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: answer => {
          this.running.set(false);
          this.groups.set(answer.groups ?? null);
          this.rows.set(answer.groups ? null : answer.items ?? []);
        },
        error: (e: ApiError) => {
          this.running.set(false);
          this.runError.set(this.lang.errorText(e));
        },
      });
  }

  /** Saves the query as a stored query that runs this QuerySpec. */
  save(): void {
    const name = this.saveName().trim();
    if (!name || !this.state().entity) return;
    this.api.post('/api/v1/admin/queries', { name, query_spec: this.spec(), parameters: [] })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => this.saved.set(true),
        error: (e: ApiError) => this.runError.set(this.lang.errorText(e)),
      });
  }

  cell(value: unknown): string {
    if (value === null || value === undefined) return '';
    return typeof value === 'object' ? JSON.stringify(value) : String(value);
  }
}
