import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  ARCHIVE_REASONS, FieldChangeService, structureErrorText,
  type ArchiveReason, type ArchiveRow, type RestoreCounts,
} from '@attome/xrm/core/admin/data';

/**
 * Solution 7 Phase 2 (design §8.5) — the 30-day recovery archive of one
 * entity: values of deleted fields and values a type change emptied. Lists
 * rows (never the values themselves), one-based; **Restore** puts one value
 * back, **Restore all** every unexpired value of the chosen field (repeat
 * while `remaining > 0`). Restore only fills empty fields and never
 * overwrites; a deleted field must be added again first
 * (`restore_target_missing`).
 */
@Component({
  selector: 'xrm-recovery-archive',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  styleUrls: ['../../../../../styles/admin-page.css', './recovery-archive.component.css'],
  templateUrl: './recovery-archive.component.html',
})
export class RecoveryArchiveComponent implements OnInit {
  private readonly svc = inject(FieldChangeService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  /** Entity logical name. */
  readonly entity = input.required<string>();
  /** Field names to offer in the filter (archived names of deleted fields may differ). */
  readonly fieldNames = input<string[]>([]);
  /** A field to start filtered on. */
  readonly initialField = input<string>('');

  readonly reasons = ARCHIVE_REASONS;
  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly pageSize = 25;

  readonly field = signal('');
  readonly reason = signal<ArchiveReason | ''>('');
  readonly includeRestored = signal(false);

  readonly rows = signal<ArchiveRow[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly busyId = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));
  readonly hasPrevious = computed(() => this.page() > 1);
  readonly hasNext = computed(() => this.page() < this.pages());
  /** The field "Restore all" acts on: the filter's, trimmed. */
  readonly restoreAllField = computed(() => this.field().trim());

  ngOnInit(): void {
    this.field.set(this.initialField());
    this.load();
  }

  apply(): void {
    this.page.set(1);
    this.load();
  }

  previous(): void {
    if (!this.hasPrevious() || this.loading()) return;
    this.page.update(p => p - 1);
    this.load();
  }

  next(): void {
    if (!this.hasNext() || this.loading()) return;
    this.page.update(p => p + 1);
    this.load();
  }

  reasonKey(reason: string): string { return `fieldChange.archive.reasons.${reason}`; }

  restoreOne(row: ArchiveRow): void {
    if (this.busyId()) return;
    this.busyId.set(row.id);
    this.notice.set(null);
    this.error.set(null);
    this.svc.restoreArchived(row.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: counts => { this.busyId.set(null); this.showCounts(counts, false); this.load(); },
      error: (err: ApiError) => { this.busyId.set(null); this.error.set(structureErrorText(this.lang, err)); },
    });
  }

  restoreAll(): void {
    const field = this.restoreAllField();
    if (!field || this.busyId()) return;
    this.busyId.set('*');
    this.notice.set(null);
    this.error.set(null);
    this.svc.restoreField(this.entity(), field).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: counts => { this.busyId.set(null); this.showCounts(counts, true); this.load(); },
      error: (err: ApiError) => { this.busyId.set(null); this.error.set(structureErrorText(this.lang, err)); },
    });
  }

  private showCounts(counts: RestoreCounts, perField: boolean): void {
    const text = this.lang.translate('fieldChange.archive.result', {
      restored: counts.restored,
      filled: counts.skipped_filled,
      notConvertible: counts.skipped_not_convertible,
      missing: counts.missing_records,
    });
    const more = perField && counts.remaining > 0
      ? ' ' + this.lang.translate('fieldChange.archive.remaining', { count: counts.remaining })
      : '';
    this.notice.set(text + more);
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listArchive({
      entity: this.entity(),
      field: this.field().trim() || undefined,
      reason: this.reason() || undefined,
      include_restored: this.includeRestored(),
    }, this.page(), this.pageSize).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => { this.rows.set(res.items); this.total.set(res.total); this.loading.set(false); },
      error: (err: ApiError) => { this.error.set(structureErrorText(this.lang, err)); this.loading.set(false); },
    });
  }
}
