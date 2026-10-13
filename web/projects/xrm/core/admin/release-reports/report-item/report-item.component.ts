import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, output, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Observable } from 'rxjs';
import { LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  ARCHIVE_BACKED_KINDS, ReleaseReportService, stableErrorCode, structureErrorText,
  type ItemRestoreResult, type ReportItem, type ReportItemKind, type ReportItemView,
} from '@attome/xrm/core/admin/data';
import { describeItem, formatValue } from '../report-text';

type Action = 'accept' | 'useMine' | 'restore' | 'dismiss';

/**
 * One release-report item (design §10.2): what happened in plain words, a
 * conflict's two values, and the decisions that apply to it. Every decision
 * sends the item's `row_version` as `If-Match`; a stale item (409
 * `version_conflict`) or one someone else decided (`report_item_decided`)
 * asks the page to reload (`stale`). Nothing here has a deadline.
 */
@Component({
  selector: 'attome-report-item',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  styleUrls: ['../../../../styles/admin-page.css', './report-item.component.css'],
  templateUrl: './report-item.component.html',
})
export class ReportItemComponent implements OnInit {
  private readonly svc = inject(ReleaseReportService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly item = input.required<ReportItemView>();
  /** The item after a decision (values kept from the view). */
  readonly changed = output<ReportItemView>();
  /** The item changed under us: the page reloads it. */
  readonly stale = output<void>();

  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };

  /**
   * The record's `row_version` read when this item was shown, sent with Use
   * mine so the server refuses (409) when the record changed after the
   * administrator looked — never re-read at click time, which would defeat
   * that check. `null` until read (Use mine waits for it).
   */
  readonly seenRecordVersion = signal<number | null>(null);

  readonly busy = signal<Action | null>(null);
  readonly notice = signal<string | null>(null);
  readonly error = signal<string | null>(null);

  readonly sentence = computed(() => describeItem(this.lang, this.item()));
  readonly isOpen = computed(() => this.item().status === 'open');
  readonly isConflict = computed(() => this.item().kind === 'conflict');
  readonly canDecideConflict = computed(() => this.isOpen() && this.isConflict());
  readonly canUseMine = computed(() =>
    this.canDecideConflict() && this.item().has_values && !this.item().values_hidden);
  /** A record conflict needs the record version it was shown with. */
  readonly useMineReady = computed(() => !this.item().record_id || this.seenRecordVersion() !== null);

  ngOnInit(): void {
    const it = this.item();
    if (!it.record_id || !this.canUseMine()) return;
    this.svc.recordRowVersion(it.entity_logicalname, it.record_id)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: rv => this.seenRecordVersion.set(rv),
        // The record is gone or unreadable: Use mine stays unavailable and
        // Accept / Dismiss still work.
        error: (err: ApiError) => this.error.set(structureErrorText(this.lang, err)),
      });
  }
  readonly canRestore = computed(() =>
    this.isOpen() && ARCHIVE_BACKED_KINDS.includes(this.item().kind as ReportItemKind));
  readonly canDismiss = computed(() => this.item().status === 'open' || this.item().status === 'info');
  readonly valuesMissing = computed(() =>
    this.isConflict() && !this.item().has_values && !this.item().values_hidden);

  /** Shown values of a conflict, as text. */
  value(which: 'theirs' | 'ours' | 'key'): string {
    const values = this.item().values;
    return formatValue(this.lang, values ? values[which] : null);
  }

  hasKey(): boolean {
    const key = this.item().values?.key;
    return key !== undefined && key !== null;
  }

  kindKey(): string { return `releaseReport.kinds.${this.item().kind}`; }
  statusKey(): string { return `releaseReport.itemStatus.${this.item().status}`; }

  accept(): void {
    this.run('accept', this.svc.accept(this.item()), item => {
      this.notice.set(this.lang.translate('releaseReport.results.accepted'));
      this.emitChanged(item);
    });
  }

  useMine(): void {
    const it = this.item();
    const seen = this.seenRecordVersion();
    if (it.record_id && seen === null) return;
    const write$: Observable<ReportItem> = it.record_id
      ? this.svc.useMine(it, seen ?? undefined)
      : this.svc.useMine(it);
    this.run('useMine', write$, item => {
      this.notice.set(this.lang.translate('releaseReport.results.usedMine'));
      this.emitChanged(item);
    });
  }

  dismiss(): void {
    this.run('dismiss', this.svc.dismiss(this.item()), item => {
      this.notice.set(this.lang.translate('releaseReport.results.dismissed'));
      this.emitChanged(item);
    });
  }

  restore(): void {
    this.run('restore', this.svc.restore(this.item().id), (res: ItemRestoreResult) => {
      const counts = this.lang.translate('releaseReport.results.restored', {
        restored: res.restore.restored,
        filled: res.restore.skipped_filled,
        notConvertible: res.restore.skipped_not_convertible,
        missing: res.restore.missing_records,
      });
      const remaining = res.remaining > 0
        ? ' ' + this.lang.translate('releaseReport.results.remaining', { count: res.remaining })
        : '';
      this.notice.set(counts + remaining);
      this.emitChanged(res.item);
    });
  }

  private emitChanged(item: ReportItem): void {
    const view = this.item();
    this.changed.emit({ ...view, ...item, values: view.values, values_hidden: view.values_hidden });
  }

  private run<T>(action: Action, call$: Observable<T>, done: (value: T) => void): void {
    if (this.busy()) return;
    this.busy.set(action);
    this.notice.set(null);
    this.error.set(null);
    call$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: value => { this.busy.set(null); done(value); },
      error: (err: ApiError) => {
        this.busy.set(null);
        this.error.set(structureErrorText(this.lang, err));
        const code = stableErrorCode(err);
        if (code === 'version_conflict' || code === 'report_item_decided') this.stale.emit();
      },
    });
  }
}
