import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, TranslatePipe } from '@attome/base';
import { DashboardService, SpreadTargetResult } from '@attome/xrm/dashboard/data';

/** One member's share, in percent, as typed. */
export interface ShareRow { member: string; percent: number | null; }

/** The shares as the spread route takes them (fractions of 1), or `null`
 * when a member is blank, a share is missing or negative, or the shares do
 * not add up to 100% (within half a percent). Pure. */
export function sharesBody(rows: readonly ShareRow[]): Record<string, number> | null {
  if (rows.length === 0) return null;
  const out: Record<string, number> = {};
  let sum = 0;
  for (const row of rows) {
    const member = row.member.trim();
    if (!member || row.percent === null || !Number.isFinite(row.percent) || row.percent < 0) return null;
    out[member] = row.percent / 100;
    sum += row.percent;
  }
  return Math.abs(sum - 100) <= 0.5 ? out : null;
}

/** Each member's target for `total` at the typed shares, for the preview. Pure. */
export function previewChildren(total: number | null, rows: readonly ShareRow[]): { member: string; value: number }[] {
  if (total === null || !Number.isFinite(total)) return [];
  return rows
    .filter(r => r.member.trim() && r.percent !== null)
    .map(r => ({ member: r.member.trim(), value: Math.round(total * (r.percent ?? 0)) / 100 }));
}

/**
 * P9-T15: spreads a metric's target for one period to the members of a
 * dimension: by the shares typed here (which must add up to 100%) or by last
 * year's actuals, with a preview of each member's share before it is sent
 * (`POST /api/v1/metrics/{id}/targets/spread`).
 */
@Component({
  selector: 'attome-target-spread-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  templateUrl: './target-spread-dialog.component.html',
  styleUrls: ['./target-spread-dialog.component.css'],
})
export class TargetSpreadDialogComponent {
  private readonly svc = inject(DashboardService);

  readonly metricId = input.required<string>();
  readonly periodStart = input.required<string>();
  readonly closed = output<SpreadTargetResult | null>();

  readonly total = signal<number | null>(null);
  readonly method = signal<'share' | 'last_year'>('share');
  readonly dimension = signal('');
  readonly rows = signal<ShareRow[]>([{ member: '', percent: null }]);
  readonly saving = signal(false);
  readonly error = signal<string | null>(null);

  readonly shares = computed(() => sharesBody(this.rows()));
  readonly preview = computed(() => previewChildren(this.total(), this.rows()));
  readonly percentSum = computed(() => this.rows().reduce((s, r) => s + (r.percent ?? 0), 0));
  readonly canSave = computed(() => !this.saving() && this.total() !== null && !!this.dimension().trim()
    && (this.method() === 'last_year' || this.shares() !== null));

  setRow(index: number, patch: Partial<ShareRow>): void {
    this.rows.update(rows => rows.map((r, i) => (i === index ? { ...r, ...patch } : r)));
  }

  addRow(): void {
    this.rows.update(rows => [...rows, { member: '', percent: null }]);
  }

  removeRow(index: number): void {
    this.rows.update(rows => rows.filter((_, i) => i !== index));
  }

  save(): void {
    const total = this.total();
    if (!this.canSave() || total === null) return;
    this.saving.set(true);
    this.error.set(null);
    const shares = this.method() === 'share' ? this.shares() ?? undefined : undefined;
    this.svc.spreadTarget(this.metricId(), {
      period_start: `${this.periodStart()}T00:00:00Z`,
      total,
      method: this.method(),
      dimension_attribute: this.dimension().trim(),
      shares,
    }).subscribe({
      next: result => {
        this.saving.set(false);
        this.closed.emit(result);
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.error.set(e?.message || 'metricViews.spread.failed');
      },
    });
  }

  cancel(): void {
    this.closed.emit(null);
  }
}
