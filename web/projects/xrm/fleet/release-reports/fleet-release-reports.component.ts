import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { NgTemplateOutlet } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fleetErrorText } from '../data/fleet-error-text';
import { fleetLabel, valueText, type FleetLabelSet } from '../data/fleet-labels';
import {
  FLEET_ITEM_KINDS, FLEET_ITEM_STATUSES, FLEET_REPORT_STATUSES,
  type DeploymentView, type FleetReleaseReport, type FleetReportItem, type ItemDecision, type OpenItemView,
} from '../data/fleet.types';

/** The words for a decision, in the "done" notice. */
const DECISION_KEYS: Record<ItemDecision, string> = {
  'accept':   'fleet.reports.accept',
  'use-mine': 'fleet.reports.useMine',
  'dismiss':  'fleet.reports.dismiss',
};

/**
 * `/xrm/fleet/release-reports` (D-792 F2): release-report items across every
 * customer. The top list is every open item in the fleet, oldest first; below
 * it, one customer's reports and a report's items. Every read and decision goes
 * to the customer server through its rollout credential and is audited there.
 * Accept, Use mine and Dismiss send the item's `row_version`; Use mine on a
 * record conflict also needs the record's `row_version`, which the console
 * cannot read, so the developer types it in (`?deployment=<id>` preselects a
 * customer, from the deployment page).
 */
@Component({
  selector: 'attome-fleet-release-reports',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, NgTemplateOutlet, RouterLink, LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', '../fleet.css', './fleet-release-reports.component.css'],
  templateUrl: './fleet-release-reports.component.html',
})
export class FleetReleaseReportsComponent implements OnInit {
  private readonly svc = inject(FleetService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  /** `?deployment=<id>` (`withComponentInputBinding()`). */
  readonly deployment = input<string | undefined>(undefined);

  readonly reportStatuses = FLEET_REPORT_STATUSES;
  readonly itemStatuses = FLEET_ITEM_STATUSES;
  readonly itemKinds = FLEET_ITEM_KINDS;
  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly openPageSize = 25;
  readonly reportsPageSize = 20;
  readonly itemsPageSize = 25;

  // ── Fleet-wide open items ───────────────────────────────────────────────
  readonly openItems = signal<OpenItemView[]>([]);
  readonly openTotal = signal(0);
  readonly openPage = signal(1);
  readonly openLoading = signal(true);
  readonly openError = signal<string | null>(null);
  readonly openPages = computed(() => Math.max(1, Math.ceil(this.openTotal() / this.openPageSize)));

  // ── One customer ────────────────────────────────────────────────────────
  readonly deployments = signal<DeploymentView[]>([]);
  readonly deploymentsError = signal<string | null>(null);
  readonly selectedDeployment = signal('');
  readonly reportStatus = signal('');
  readonly reports = signal<FleetReleaseReport[]>([]);
  readonly reportsTotal = signal(0);
  readonly reportsPage = signal(1);
  readonly reportsLoading = signal(false);
  readonly reportsError = signal<string | null>(null);
  readonly reportsPages = computed(() => Math.max(1, Math.ceil(this.reportsTotal() / this.reportsPageSize)));

  readonly selectedReport = signal<FleetReleaseReport | null>(null);
  readonly itemStatus = signal('open');
  readonly itemKind = signal('');
  readonly items = signal<FleetReportItem[]>([]);
  readonly itemsTotal = signal(0);
  readonly itemsPage = signal(1);
  readonly itemsLoading = signal(false);
  readonly itemsError = signal<string | null>(null);
  readonly itemsPages = computed(() => Math.max(1, Math.ceil(this.itemsTotal() / this.itemsPageSize)));

  // ── Decisions ───────────────────────────────────────────────────────────
  readonly busyItem = signal<string | null>(null);
  readonly itemErrors = signal<Record<string, string>>({});
  /** The record `row_version` typed in for Use mine on a record conflict, by item id. */
  readonly recordVersions = signal<Record<string, string>>({});
  readonly notice = signal<string | null>(null);

  /** Deployments the console can read reports from (a stored credential). */
  readonly readable = computed(() => this.deployments().filter(d => d.has_credential));
  readonly selectedLabel = computed(() =>
    this.deployments().find(d => d.id === this.selectedDeployment())?.label ?? '');

  constructor() {
    effect(() => {
      const wanted = this.deployment();
      if (!wanted) return;
      untracked(() => {
        if (this.selectedDeployment() !== wanted) this.chooseDeployment(wanted);
      });
    });
  }

  ngOnInit(): void {
    this.loadOpen();
    this.svc.allDeployments(false).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: list => this.deployments.set(list),
      error: (err: ApiError) => this.deploymentsError.set(fleetErrorText(this.lang, err)),
    });
  }

  text(set: FleetLabelSet, value: string | null | undefined): string {
    return fleetLabel(this.lang, set, value);
  }

  value(v: unknown): string {
    return valueText(v);
  }

  /** `entity.field`, or just the entity. */
  itemPath(item: FleetReportItem): string {
    return item.field_logicalname ? `${item.entity_logicalname}.${item.field_logicalname}` : item.entity_logicalname;
  }

  canAccept(item: FleetReportItem): boolean {
    return item.status === 'open' && item.kind === 'conflict';
  }

  canUseMine(item: FleetReportItem): boolean {
    return this.canAccept(item) && item.has_values && !item.values_hidden;
  }

  canDismiss(item: FleetReportItem): boolean {
    return item.status === 'open' || item.status === 'info';
  }

  /** A record conflict needs the record's `row_version` before Use mine. */
  needsRecordVersion(item: FleetReportItem): boolean {
    return this.canUseMine(item) && item.record_id !== null;
  }

  recordVersionOf(itemId: string): string {
    return this.recordVersions()[itemId] ?? '';
  }

  setRecordVersion(itemId: string, value: string): void {
    this.recordVersions.update(map => ({ ...map, [itemId]: value }));
  }

  useMineReady(item: FleetReportItem): boolean {
    if (!this.needsRecordVersion(item)) return true;
    return /^\d+$/.test(this.recordVersionOf(item.id).trim());
  }

  // ── Open items ──────────────────────────────────────────────────────────

  loadOpen(): void {
    this.openLoading.set(true);
    this.openError.set(null);
    this.svc.openItems(this.openPage(), this.openPageSize).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.openItems.set(res.items);
        this.openTotal.set(res.total);
        this.openLoading.set(false);
      },
      error: (err: ApiError) => {
        this.openError.set(fleetErrorText(this.lang, err));
        this.openLoading.set(false);
      },
    });
  }

  openPrevious(): void {
    if (this.openPage() <= 1 || this.openLoading()) return;
    this.openPage.update(p => p - 1);
    this.loadOpen();
  }

  openNext(): void {
    if (this.openPage() >= this.openPages() || this.openLoading()) return;
    this.openPage.update(p => p + 1);
    this.loadOpen();
  }

  // ── One customer's reports and items ────────────────────────────────────

  chooseDeployment(id: string): void {
    this.selectedDeployment.set(id);
    this.selectedReport.set(null);
    this.items.set([]);
    this.reportsPage.set(1);
    this.loadReports();
  }

  applyReportFilter(): void {
    this.reportsPage.set(1);
    this.loadReports();
  }

  loadReports(): void {
    const id = this.selectedDeployment();
    if (!id) {
      this.reports.set([]);
      this.reportsTotal.set(0);
      return;
    }
    this.reportsLoading.set(true);
    this.reportsError.set(null);
    this.svc.listReports(id, this.reportStatus() || null, this.reportsPage(), this.reportsPageSize)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: res => {
          this.reports.set(res.items);
          this.reportsTotal.set(res.total);
          this.reportsLoading.set(false);
        },
        error: (err: ApiError) => {
          this.reportsError.set(fleetErrorText(this.lang, err));
          this.reportsLoading.set(false);
        },
      });
  }

  reportsPrevious(): void {
    if (this.reportsPage() <= 1 || this.reportsLoading()) return;
    this.reportsPage.update(p => p - 1);
    this.loadReports();
  }

  reportsNext(): void {
    if (this.reportsPage() >= this.reportsPages() || this.reportsLoading()) return;
    this.reportsPage.update(p => p + 1);
    this.loadReports();
  }

  openReport(report: FleetReleaseReport): void {
    this.selectedReport.set(report);
    this.itemsPage.set(1);
    this.loadItems();
  }

  closeReport(): void {
    this.selectedReport.set(null);
    this.items.set([]);
  }

  applyItemFilter(): void {
    this.itemsPage.set(1);
    this.loadItems();
  }

  loadItems(): void {
    const report = this.selectedReport();
    const id = this.selectedDeployment();
    if (!report || !id) return;
    this.itemsLoading.set(true);
    this.itemsError.set(null);
    const filter = { status: this.itemStatus() || undefined, kind: this.itemKind() || undefined };
    this.svc.listItems(id, report.id, filter, this.itemsPage(), this.itemsPageSize)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: res => {
          this.items.set(res.items);
          this.itemsTotal.set(res.total);
          this.itemsLoading.set(false);
        },
        error: (err: ApiError) => {
          this.itemsError.set(fleetErrorText(this.lang, err));
          this.itemsLoading.set(false);
        },
      });
  }

  itemsPrevious(): void {
    if (this.itemsPage() <= 1 || this.itemsLoading()) return;
    this.itemsPage.update(p => p - 1);
    this.loadItems();
  }

  itemsNext(): void {
    if (this.itemsPage() >= this.itemsPages() || this.itemsLoading()) return;
    this.itemsPage.update(p => p + 1);
    this.loadItems();
  }

  // ── Decisions ───────────────────────────────────────────────────────────

  decide(deploymentId: string, item: FleetReportItem, decision: ItemDecision): void {
    if (this.busyItem()) return;
    let recordVersion: number | null = null;
    if (decision === 'use-mine') {
      if (!this.useMineReady(item)) return;
      if (this.needsRecordVersion(item)) recordVersion = Number(this.recordVersionOf(item.id).trim());
    }
    this.busyItem.set(item.id);
    this.notice.set(null);
    this.clearItemError(item.id);
    this.svc.decideItem(deploymentId, item.id, decision, item.row_version, recordVersion)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: decided => {
          this.busyItem.set(null);
          // The customer answers with the item without its values; keep the
          // ones already shown and take everything else from the answer.
          const merged: FleetReportItem = { ...item, ...decided, values: item.values, values_hidden: item.values_hidden };
          this.items.update(list => list.map(i => (i.id === item.id ? merged : i)));
          this.openItems.update(list => list.map(o => (o.item.id === item.id ? { ...o, item: merged } : o)));
          this.notice.set(this.lang.translate('fleet.reports.decided', {
            decision: this.lang.translate(DECISION_KEYS[decision]),
          }));
        },
        error: (err: ApiError) => {
          this.busyItem.set(null);
          this.itemErrors.update(map => ({ ...map, [item.id]: fleetErrorText(this.lang, err) }));
        },
      });
  }

  itemError(itemId: string): string | null {
    return this.itemErrors()[itemId] ?? null;
  }

  private clearItemError(itemId: string): void {
    this.itemErrors.update(map => {
      const next = { ...map };
      delete next[itemId];
      return next;
    });
  }
}
