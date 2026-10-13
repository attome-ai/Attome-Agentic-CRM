import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiError } from '@attome/base';

import {
  ApplyAccepted,
  BundleAdminService,
  DriftReport,
  PlanListItem,
} from '../../../services/bundle-admin.service';

/** One named bundle's installed state — every `succeeded` ledger row sharing
 * a `bundle_name`, newest first. `latest` drives the summary row; `history`
 * (everything, including `latest`) is what the rollback picker offers. */
interface InstalledBundle {
  name:    string;
  latest:  PlanListItem;
  history: PlanListItem[];
}

@Component({
  selector:   'xrm-bundle-lifecycle-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, DatePipe],
  styleUrls:  ['../../../../styles/admin-page.css', './bundle-lifecycle-list.component.css'],
  templateUrl: './bundle-lifecycle-list.component.html',
})
export class BundleLifecycleListComponent implements OnInit {
  private readonly svc = inject(BundleAdminService);

  readonly loading = signal(true);
  readonly error   = signal<string | null>(null);

  readonly installed = signal<InstalledBundle[]>([]);
  readonly pending    = signal<PlanListItem[]>([]);
  readonly drift       = signal<DriftReport | null>(null);
  readonly driftLoading = signal(true);
  readonly driftError   = signal<string | null>(null);

  // Rollback panel state — at most one bundle's picker open at a time.
  readonly rollbackTarget  = signal<string | null>(null);
  readonly rollbackVersion = signal('');
  readonly allowRetire     = signal(false);
  readonly rollingBack     = signal(false);
  readonly rollbackError   = signal<string | null>(null);
  readonly rollbackResult  = signal<ApplyAccepted | null>(null);

  readonly pendingCount = computed(() => this.pending().length);

  ngOnInit(): void {
    this.loadLedger();
    this.loadDrift();
  }

  private loadLedger(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listPlans('succeeded').subscribe({
      next: rows => {
        this.installed.set(groupByBundleName(rows));
        this.loading.set(false);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
    this.loadPending();
  }

  private loadPending(): void {
    // Two lifecycle states count as "pending": a computed-but-not-yet-queued
    // plan, and a queued-but-not-yet-claimed one. `applying`/`claimed` rows
    // are mid-run rather than pending, but are rare/short-lived enough that a
    // Phase 1 list does not need a third call for them.
    this.svc.listPlans('planned').subscribe({
      next: planned => {
        this.svc.listPlans('queued').subscribe({
          next: queued => {
            const merged = [...planned, ...queued].sort((a, b) => b.created_at.localeCompare(a.created_at));
            this.pending.set(merged);
          },
          error: () => { /* non-fatal — installed-bundles view still works */ },
        });
      },
      error: () => { /* non-fatal */ },
    });
  }

  private loadDrift(): void {
    this.driftLoading.set(true);
    this.driftError.set(null);
    this.svc.getDrift().subscribe({
      next: d => { this.drift.set(d); this.driftLoading.set(false); },
      error: (e: ApiError) => { this.driftError.set(e.message); this.driftLoading.set(false); },
    });
  }

  openRollback(bundle: InstalledBundle): void {
    this.rollbackTarget.set(bundle.name);
    // Default to the version immediately before the latest one, if any —
    // the common "undo the last apply" case (verticals skill's documented
    // procedure).
    const prior = bundle.history.find(h => h !== bundle.latest);
    this.rollbackVersion.set(prior?.bundle_version ?? '');
    this.allowRetire.set(false);
    this.rollbackError.set(null);
    this.rollbackResult.set(null);
  }

  closeRollback(): void {
    this.rollbackTarget.set(null);
  }

  submitRollback(): void {
    const name = this.rollbackTarget();
    const to_version = this.rollbackVersion().trim();
    if (!name || !to_version) {
      this.rollbackError.set('Choose a target version.');
      return;
    }
    this.rollingBack.set(true);
    this.rollbackError.set(null);
    this.svc.rollback(name, { to_version, allow_retire: this.allowRetire() }).subscribe({
      next: res => {
        this.rollingBack.set(false);
        this.rollbackResult.set(res);
        // Refresh the ledger/drift once the rollback plan is queued (or an
        // approval was requested) so the new row shows up in "pending".
        this.loadLedger();
        this.loadDrift();
      },
      error: (e: ApiError) => { this.rollingBack.set(false); this.rollbackError.set(e.message); },
    });
  }
}

/** Groups `succeeded` rows by `bundle_name`, newest (`finished_at`/`created_at`)
 * first within each group; rows with no `bundle_name` (an anonymous
 * whole-deployment apply — `Bundle.name` unset) are not a "named bundle" and
 * are excluded, matching `Bundle.name`'s own doc comment. */
function groupByBundleName(rows: PlanListItem[]): InstalledBundle[] {
  const byName = new Map<string, PlanListItem[]>();
  for (const row of rows) {
    if (!row.bundle_name) continue;
    const list = byName.get(row.bundle_name) ?? [];
    list.push(row);
    byName.set(row.bundle_name, list);
  }
  const out: InstalledBundle[] = [];
  for (const [name, history] of byName) {
    // `listPlans` already returns newest-first; stable-sort defensively in
    // case a caller's ordering assumption ever changes.
    history.sort((a, b) => (b.finished_at ?? b.created_at).localeCompare(a.finished_at ?? a.created_at));
    out.push({ name, latest: history[0], history });
  }
  out.sort((a, b) => a.name.localeCompare(b.name));
  return out;
}
