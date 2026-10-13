import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  REPORT_ITEM_KINDS, REPORT_ITEM_STATUSES, ReleaseReportService, structureErrorText,
  type ItemFilter, type ReleaseReport, type ReportItemKind, type ReportItemStatus, type ReportItemView,
} from '@attome/xrm/core/admin/data';
import { ReportItemComponent } from '../report-item/report-item.component';

/**
 * Solution 7 Phase 2 (design §10) — `/xrm/admin/release-reports/{id}`: one
 * release report, its counts, and its items filtered by kind, status and
 * entity (one-based paging). The decisions live on each item
 * (`ReportItemComponent`); a stale decision reloads the current page and
 * says so. Nothing here has a deadline or blocks anything.
 */
@Component({
  selector: 'xrm-release-report-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, LocalDatePipe, LocalNumberPipe, TranslatePipe, ReportItemComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../release-reports.css', './release-report-detail.component.css'],
  templateUrl: './release-report-detail.component.html',
})
export class ReleaseReportDetailComponent {
  private readonly svc = inject(ReleaseReportService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  /** The report id (route param, `withComponentInputBinding()`). */
  readonly id = input.required<string>();

  readonly kinds = REPORT_ITEM_KINDS;
  readonly itemStatuses = REPORT_ITEM_STATUSES;
  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly pageSize = 25;

  readonly report = signal<ReleaseReport | null>(null);
  readonly reportLoading = signal(true);
  readonly reportError = signal<string | null>(null);

  readonly kind = signal<ReportItemKind | ''>('');
  /** Open items first: that is what the administrator came for. */
  readonly itemStatus = signal<ReportItemStatus | ''>('open');
  readonly entity = signal('');

  readonly items = signal<ReportItemView[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly itemsLoading = signal(true);
  readonly itemsError = signal<string | null>(null);
  /** Set after a stale decision reloaded the page. */
  readonly notice = signal<string | null>(null);

  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));
  readonly hasPrevious = computed(() => this.page() > 1);
  readonly hasNext = computed(() => this.page() < this.pages());

  constructor() {
    // Load on the first id and again whenever the route reuses this page for
    // another report (a notification link opened while a report is shown).
    effect(() => {
      this.id();
      untracked(() => {
        this.page.set(1);
        this.notice.set(null);
        this.report.set(null);
        this.reportLoading.set(true);
        this.loadReport();
        this.loadItems();
      });
    });
  }

  apply(): void {
    this.page.set(1);
    this.notice.set(null);
    this.loadItems();
  }

  reset(): void {
    this.kind.set('');
    this.itemStatus.set('open');
    this.entity.set('');
    this.apply();
  }

  previous(): void {
    if (!this.hasPrevious() || this.itemsLoading()) return;
    this.page.update(p => p - 1);
    this.loadItems();
  }

  next(): void {
    if (!this.hasNext() || this.itemsLoading()) return;
    this.page.update(p => p + 1);
    this.loadItems();
  }

  kindKey(kind: string): string { return `releaseReport.kinds.${kind}`; }
  itemStatusKey(status: string): string { return `releaseReport.itemStatus.${status}`; }
  statusKey(status: string): string { return `releaseReport.status.${status}`; }
  sourceKey(source: string): string { return `releaseReport.source.${source}`; }

  /** A decision succeeded: show the new state in place and refresh the counts. */
  onChanged(updated: ReportItemView): void {
    this.items.update(rows => rows.map(r => (r.id === updated.id ? updated : r)));
    this.loadReport();
  }

  /** A decision met a stale item: reload this page and say why. */
  onStale(): void {
    this.notice.set(this.lang.translate('releaseReport.detail.reloaded'));
    this.loadReport();
    this.loadItems();
  }

  private loadReport(): void {
    this.reportError.set(null);
    this.svc.getReport(this.id()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => { this.report.set(r); this.reportLoading.set(false); },
      error: (err: ApiError) => {
        this.reportError.set(err.kind === 'not_found'
          ? this.lang.translate('releaseReport.detail.notFound')
          : structureErrorText(this.lang, err));
        this.reportLoading.set(false);
      },
    });
  }

  private loadItems(): void {
    this.itemsLoading.set(true);
    this.itemsError.set(null);
    const filter: ItemFilter = {
      kind: this.kind() || undefined,
      status: this.itemStatus() || undefined,
      entity: this.entity().trim() || undefined,
    };
    this.svc.listItems(this.id(), filter, this.page(), this.pageSize)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: res => {
          this.items.set(res.items);
          this.total.set(res.total);
          this.itemsLoading.set(false);
        },
        error: (err: ApiError) => {
          this.itemsError.set(err.kind === 'not_found'
            ? this.lang.translate('releaseReport.detail.notFound')
            : structureErrorText(this.lang, err));
          this.itemsLoading.set(false);
        },
      });
  }
}
