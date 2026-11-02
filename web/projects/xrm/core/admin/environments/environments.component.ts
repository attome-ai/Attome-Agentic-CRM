import {
  ChangeDetectionStrategy, Component, DestroyRef, Injectable, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import type { Observable } from 'rxjs';
import { SdkService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError, Page } from '@attome/base';

/** One applied-changeset ledger row (`GET …/changesets/ledger`). */
export interface LedgerRow {
  id: string;
  changeset_id: string;
  ref: string;
  layer: string;
  scope: string;
  seq: number;
  phase: string;
  status: string;
  source: string;
  approval_ref: string | null;
  applied_count: number;
  error_message: string | null;
  created_at: string;
  finished_at: string | null;
}

/** One operation of a plan. */
export interface PlannedOp {
  seq: number;
  op: string;
  phase: string;
  target: Record<string, unknown>;
  action: string;
  reason?: string;
  risky: boolean;
}

/** One changeset of a plan. */
export interface PlannedChangeset {
  changeset_id: string;
  ref: string;
  layer: string;
  scope: string;
  status: string;
  blocked: string[];
  phases: { phase: string; status: string; applicable: boolean; operations: PlannedOp[] }[];
}

/** What applying a set of changesets here would do (`POST …/changesets/plan`). */
export interface ChangesetPlan {
  changesets: PlannedChangeset[];
  applicable: boolean;
}

const BASE = '/api/v1/admin/metadata/changesets';

/**
 * A22-T5 (V2-D1595 (3)) — this deployment's side of promotion: the
 * changeset ledger (`crates/engine/attome-api/src/changeset/apply_routes.rs`)
 * and a plan of uploaded changesets against it. Promotion itself stays in
 * the `attome promote` CLI; no other deployment's credentials are kept.
 */
@Injectable({ providedIn: 'root' })
export class EnvironmentsService {
  private readonly sdk = inject(SdkService);

  ledger(page: number, pageSize: number, status?: string): Observable<Page<LedgerRow>> {
    const query: Record<string, string> = { page: String(page), page_size: String(pageSize) };
    if (status) query['status'] = status;
    return this.sdk.get<Page<LedgerRow>>(`${BASE}/ledger`, { query });
  }

  plan(changesets: unknown[]): Observable<ChangesetPlan> {
    return this.sdk.post<ChangesetPlan>(`${BASE}/plan`, { body: { changesets } });
  }
}

/** Counts a plan's operations by what they would do. Pure. */
export function planCounts(plan: ChangesetPlan): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const cs of plan.changesets) {
    for (const phase of cs.phases) {
      for (const op of phase.operations) {
        counts[op.action] = (counts[op.action] ?? 0) + 1;
      }
    }
  }
  return counts;
}

type Tab = 'history' | 'waiting' | 'compare';

/**
 * A22-T5 — `/xrm/admin/environments`: what was promoted into this
 * deployment (the changeset ledger, newest first), what waits for a second
 * administrator's approval, and a comparison: drop the changeset files of
 * the configuration to promote and see, without applying anything, what
 * each would create, change, retire or be blocked by here.
 */
@Component({
  selector: 'xrm-environments',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  styleUrls: ['../../../styles/admin-page.css', './environments.component.css'],
  templateUrl: './environments.component.html',
})
export class EnvironmentsComponent implements OnInit {
  private readonly svc = inject(EnvironmentsService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly pageSize = 25;

  readonly tab = signal<Tab>('history');
  readonly rows = signal<LedgerRow[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly plan = signal<ChangesetPlan | null>(null);
  readonly planning = signal(false);

  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));
  readonly counts = computed(() => {
    const plan = this.plan();
    return plan ? planCounts(plan) : {};
  });

  ngOnInit(): void {
    this.load();
  }

  show(tab: Tab): void {
    if (this.tab() === tab) return;
    this.tab.set(tab);
    this.error.set(null);
    if (tab !== 'compare') {
      this.page.set(1);
      this.load();
    }
  }

  previous(): void {
    if (this.page() <= 1 || this.loading()) return;
    this.page.update(p => p - 1);
    this.load();
  }

  next(): void {
    if (this.page() >= this.pages() || this.loading()) return;
    this.page.update(p => p + 1);
    this.load();
  }

  /** Reads the chosen changeset files and plans them here. */
  async compare(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    if (files.length === 0) return;
    this.error.set(null);
    this.plan.set(null);
    let docs: unknown[];
    try {
      docs = await Promise.all(files.map(async f => JSON.parse(await f.text()) as unknown));
    } catch {
      this.error.set(this.lang.translate('environments.notJson'));
      return;
    }
    this.planning.set(true);
    this.svc.plan(docs).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: plan => { this.planning.set(false); this.plan.set(plan); },
      error: (err: ApiError) => { this.planning.set(false); this.error.set(this.lang.errorText(err)); },
    });
  }

  private load(): void {
    this.loading.set(true);
    const status = this.tab() === 'waiting' ? 'queued' : undefined;
    this.svc.ledger(this.page(), this.pageSize, status)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: res => {
          const items = this.tab() === 'waiting'
            ? res.items.filter(r => r.approval_ref !== null)
            : res.items;
          this.rows.set(items);
          this.total.set(res.total);
          this.loading.set(false);
        },
        error: (err: ApiError) => {
          this.loading.set(false);
          this.error.set(this.lang.errorText(err));
        },
      });
  }
}
