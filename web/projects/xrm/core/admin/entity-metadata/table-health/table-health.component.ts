import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiError, LangService, SdkService, TranslatePipe } from '@attome/base';
import type { ApiComponents } from '@attome/base';
import { Observable, catchError, forkJoin, map, of } from 'rxjs';

export type TableHealth = ApiComponents['schemas']['TableHealth'];
export type OrphanCount = ApiComponents['schemas']['OrphanCount'];
export type IndexAdvice = ApiComponents['schemas']['IndexAdvice'];
/** `admin::lookup_key::LookupKey` (read loosely until the API types carry it). */
export interface LookupKey {
  /** `none`, `not_valid` or `valid`. */
  state: string;
  keyed: boolean;
  target_entity: string;
  queued: boolean;
}

/** `admin::partition::PartitionStatus` (read loosely until the API types carry it). */
export interface PartitionStatus {
  entity: string;
  storage_mode: string;
  old_table_kept: boolean;
  run?: {
    id: string;
    status: string;
    rows_estimate?: number | null;
    rows_scanned: number;
    rows_written: number;
    error_message?: string | null;
  } | null;
}

/** A lookup field of the entity. */
export interface LookupField {
  id: string;
  logicalname: string;
}

/** A lookup's key, as the tab shows it. */
export interface LookupKeyRow {
  field: LookupField;
  key: LookupKey | null;
}

/** Whether a lookup can be keyed now: its delete rule allows a key and it has none, or one not yet checked. Pure. */
export function canKey(key: LookupKey | null): boolean {
  return !!key && key.keyed && !key.queued && key.state !== 'valid';
}

/** Whether a partitioning can be started: a standard table with no run under way. Pure. */
export function canPartition(status: PartitionStatus | null): boolean {
  if (!status || status.storage_mode !== 'standard' || status.old_table_kept) return false;
  const running = status.run && ['queued', 'claimed', 'running', 'paused'].includes(status.run.status);
  return !running;
}

/** The rows copied as a share of the estimate, 0 to 100. Pure. */
export function copiedPercent(status: PartitionStatus | null): number | null {
  const run = status?.run;
  if (!run?.rows_estimate) return null;
  return Math.min(100, Math.round((run.rows_written / run.rows_estimate) * 100));
}

/**
 * Y2-T15 — an entity table's health on the entity metadata screen: its size,
 * dead rows and vacuum, the lookups pointing at no record (orphans), each
 * lookup's database key (add it where the delete rule allows one), the
 * indexes slow queries ask for (apply one by making the field filterable),
 * and partitioning by created date (start it; the run's progress shows
 * here). Each part loads on its own, so one that fails does not hide the
 * rest. Logical CSS only, so it reads right to left in Arabic.
 */
@Component({
  selector: 'xrm-table-health',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="th" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="table-health">
      <div class="th-block">
        <h3>{{ 'tableHealth.table' | translate }}</h3>
        @if (health(); as h) {
          <dl class="th-facts">
            <dt>{{ 'tableHealth.rows' | translate }}</dt><dd dir="ltr">{{ h.live_rows.toLocaleString() }}</dd>
            <dt>{{ 'tableHealth.size' | translate }}</dt><dd dir="ltr">{{ megabytes(h.total_bytes) }} MB</dd>
            <dt>{{ 'tableHealth.dead' | translate }}</dt><dd dir="ltr">{{ (h.dead_ratio * 100).toFixed(1) }}%</dd>
            @if (h.growth_rows_7d !== null && h.growth_rows_7d !== undefined) {
              <dt>{{ 'tableHealth.growth' | translate }}</dt><dd dir="ltr">{{ h.growth_rows_7d.toLocaleString() }}</dd>
            }
          </dl>
          @if (h.lookups_without_index.length) {
            <p class="th-warn">{{ 'tableHealth.unindexedLookups' | translate: { fields: h.lookups_without_index.join(', ') } }}</p>
          }
        } @else if (errors()['health']; as e) {
          <p class="th-error" role="alert">{{ e }}</p>
        }
      </div>

      <div class="th-block">
        <h3>{{ 'tableHealth.orphans' | translate }}</h3>
        @if (orphans(); as list) {
          <ul class="th-list" data-orphans>
            @for (o of list; track o.attribute) {
              <li>
                <span dir="ltr">{{ o.attribute }} → {{ o.target_entity }}</span>
                <strong [class.th-bad]="o.orphans > 0" data-orphan-count>{{ o.orphans }}</strong>
              </li>
            } @empty {
              <li class="th-muted">{{ 'tableHealth.noLookups' | translate }}</li>
            }
          </ul>
        } @else if (errors()['orphans']; as e) {
          <p class="th-muted">{{ e }}</p>
        }
      </div>

      <div class="th-block">
        <h3>{{ 'tableHealth.keys' | translate }}</h3>
        <ul class="th-list">
          @for (row of keys(); track row.field.id) {
            <li>
              <span dir="ltr">{{ row.field.logicalname }}</span>
              <span>{{ (row.key ? 'tableHealth.keyState.' + row.key.state : 'tableHealth.keyUnknown') | translate }}</span>
              @if (row.key && !row.key.keyed) { <span class="th-muted">{{ 'tableHealth.keyNotKept' | translate }}</span> }
              @if (canKey(row.key)) {
                <button type="button" [disabled]="busy()" (click)="addKey(row.field)" data-add-key>{{ 'tableHealth.addKey' | translate }}</button>
              }
            </li>
          } @empty {
            <li class="th-muted">{{ 'tableHealth.noLookups' | translate }}</li>
          }
        </ul>
      </div>

      <div class="th-block">
        <h3>{{ 'tableHealth.indexes' | translate }}</h3>
        @if (advice(); as a) {
          @if (!a.available) {
            <p class="th-muted">{{ 'tableHealth.noStatistics' | translate }}</p>
          }
          <ul class="th-list">
            @for (p of a.proposals; track p.attribute) {
              <li>
                <span dir="ltr">{{ p.attribute }}</span>
                <span class="th-muted">{{ 'tableHealth.slowCalls' | translate: { calls: p.calls, ms: p.worst_mean_ms.toFixed(0) } }}</span>
                @if (p.field_id) {
                  <button type="button" [disabled]="busy()" (click)="applyIndex(p.field_id)" data-apply-index>{{ 'tableHealth.applyIndex' | translate }}</button>
                }
              </li>
            } @empty {
              <li class="th-muted">{{ 'tableHealth.noProposals' | translate }}</li>
            }
          </ul>
        } @else if (errors()['indexes']; as e) {
          <p class="th-error" role="alert">{{ e }}</p>
        }
      </div>

      <div class="th-block">
        <h3>{{ 'tableHealth.partition' | translate }}</h3>
        @if (partition(); as p) {
          <p>{{ 'tableHealth.mode.' + p.storage_mode | translate }}</p>
          @if (p.run; as run) {
            <p data-partition-run>
              {{ 'tableHealth.runStatus' | translate: { status: run.status } }}
              @if (percent() !== null) { <span dir="ltr">({{ percent() }}%)</span> }
            </p>
            @if (run.error_message) { <p class="th-error">{{ run.error_message }}</p> }
          }
          @if (p.old_table_kept) { <p class="th-muted">{{ 'tableHealth.oldKept' | translate: { table: p.entity + '__old' } }}</p> }
          @if (canPartition(p)) {
            <button type="button" [disabled]="busy()" (click)="startPartition()" data-start-partition>{{ 'tableHealth.startPartition' | translate }}</button>
          }
        } @else if (errors()['partition']; as e) {
          <p class="th-error" role="alert">{{ e }}</p>
        }
      </div>

      @if (notice(); as n) { <p role="status" class="th-notice">{{ n | translate }}</p> }
      @if (actionError(); as e) { <p role="alert" class="th-error">{{ e }}</p> }
    </section>
  `,
  styles: [`
    .th { display: grid; gap: 1rem; grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr)); }
    .th-block { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; }
    .th-block h3 { margin: 0 0 .5rem; font-size: 1rem; }
    .th-facts { display: grid; grid-template-columns: max-content 1fr; gap: .25rem .75rem; margin: 0; }
    .th-facts dd { margin: 0; }
    .th-list { margin: 0; padding: 0; list-style: none; display: grid; gap: .375rem; }
    .th-list li { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; }
    .th-muted { color: var(--color-text-secondary, #666); margin: 0; }
    .th-warn { color: var(--color-warning, #b7791f); margin-block-start: .5rem; }
    .th-bad { color: var(--color-danger, #c53030); }
    .th-error { color: var(--color-danger, #c53030); margin: 0; }
    .th-notice { grid-column: 1 / -1; margin: 0; }
  `],
})
export class TableHealthComponent {
  private readonly sdk = inject(SdkService);
  protected readonly lang = inject(LangService);

  /** The entity's id. */
  readonly entityId = input.required<string>();
  /** Its lookup fields. */
  readonly lookups = input<readonly LookupField[]>([]);

  readonly health = signal<TableHealth | null>(null);
  readonly orphans = signal<OrphanCount[] | null>(null);
  readonly keys = signal<LookupKeyRow[]>([]);
  readonly advice = signal<IndexAdvice | null>(null);
  readonly partition = signal<PartitionStatus | null>(null);
  readonly errors = signal<Record<string, string>>({});
  readonly busy = signal(false);
  readonly notice = signal<string | null>(null);
  readonly actionError = signal<string | null>(null);
  protected readonly percent = computed(() => copiedPercent(this.partition()));
  protected readonly canKey = canKey;
  protected readonly canPartition = canPartition;

  constructor() {
    effect(() => {
      const id = this.entityId();
      const lookups = this.lookups();
      untracked(() => this.load(id, lookups));
    });
  }

  protected megabytes(bytes: number): string {
    return (bytes / (1024 * 1024)).toFixed(1);
  }

  private base(id: string): string {
    return `/api/v1/admin/entities/${encodeURIComponent(id)}`;
  }

  private fail(part: string, e: ApiError): void {
    this.errors.update(all => ({ ...all, [part]: this.lang.errorText(e) }));
  }

  load(id: string, lookups: readonly LookupField[]): void {
    this.errors.set({});
    this.sdk.get<TableHealth>(`${this.base(id)}/health`).subscribe({
      next: h => this.health.set(h),
      error: (e: ApiError) => this.fail('health', e),
    });
    this.sdk.get<{ items: OrphanCount[] }>(`${this.base(id)}/orphans`, { query: { page: 1, page_size: 100 } }).subscribe({
      next: page => this.orphans.set(page.items ?? []),
      error: (e: ApiError) => this.fail('orphans', e),
    });
    this.sdk.get<IndexAdvice>(`${this.base(id)}/index-proposals`).subscribe({
      next: a => this.advice.set(a),
      error: (e: ApiError) => this.fail('indexes', e),
    });
    this.loadPartition(id);
    const reads: Observable<LookupKeyRow>[] = lookups.map(field =>
      this.sdk.get<LookupKey>(`${this.base(id)}/fields/${encodeURIComponent(field.id)}/foreign-key`).pipe(
        map(key => ({ field, key })),
        catchError(() => of({ field, key: null })),
      ));
    if (reads.length) forkJoin(reads).subscribe(rows => this.keys.set(rows));
    else this.keys.set([]);
  }

  private loadPartition(id: string): void {
    this.sdk.get<PartitionStatus>(`${this.base(id)}/partition`).subscribe({
      next: p => this.partition.set(p),
      error: (e: ApiError) => this.fail('partition', e),
    });
  }

  private act(call: Observable<unknown>, notice: string): void {
    this.busy.set(true);
    this.notice.set(null);
    this.actionError.set(null);
    call.subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set(notice);
        this.load(this.entityId(), this.lookups());
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.actionError.set(this.lang.errorText(e));
      },
    });
  }

  addKey(field: LookupField): void {
    this.act(
      this.sdk.post(`${this.base(this.entityId())}/fields/${encodeURIComponent(field.id)}/foreign-key`, { body: {} }),
      'tableHealth.keyAdded',
    );
  }

  /** An index proposal is applied by making the field filterable, which builds its index. */
  applyIndex(fieldId: string): void {
    this.act(
      this.sdk.patch(`${this.base(this.entityId())}/fields/${encodeURIComponent(fieldId)}`, { body: { is_filterable: true } }),
      'tableHealth.indexApplied',
    );
  }

  startPartition(): void {
    this.act(this.sdk.post(`${this.base(this.entityId())}/partition`, { body: {} }), 'tableHealth.partitionStarted');
  }
}
