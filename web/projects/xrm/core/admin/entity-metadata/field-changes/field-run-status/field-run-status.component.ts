import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, output, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import {
  FieldChangeService, structureErrorText, type AbandonedFieldRun, type DataStepRunStatus,
} from '@attome/xrm/core/admin/data';
import { catchError, interval, of, startWith, switchMap, takeWhile } from 'rxjs';

/** A run in these states may still change; the screen keeps polling it. */
const LIVE = ['queued', 'claimed', 'running', 'paused'];

/** How often a live run's progress is read again. */
const POLL_MS = 5000;

/**
 * The background run of a field change on a large table (a type change's
 * `retype`, a delete's `archive` copy), roadmap Y12-T13: its status, rows
 * done and ETA, read from `GET /api/v1/admin/data-step-runs/{id}` every five
 * seconds while it runs, with **Pause**, **Resume** and **Cancel** (Y12-T5).
 * A failed or cancelled run offers **Abandon** (`POST …/runs/{run_id}/abandon`):
 * it drops a retype's unfinished shadow column and frees the field.
 */
@Component({
  selector: 'attome-field-run-status',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../../../../../styles/admin-page.css', './field-run-status.component.css'],
  templateUrl: './field-run-status.component.html',
})
export class FieldRunStatusComponent implements OnInit {
  private readonly svc = inject(FieldChangeService);
  private readonly lang = inject(LangService);
  private readonly confirm = inject(ConfirmService);
  private readonly destroyRef = inject(DestroyRef);

  readonly entityId = input.required<string>();
  readonly fieldId = input.required<string>();
  readonly runId = input.required<string>();

  /** The run was abandoned: the field is free again. */
  readonly abandoned = output<AbandonedFieldRun>();

  readonly busy = signal(false);
  readonly outcome = signal<AbandonedFieldRun | null>(null);
  readonly error = signal<string | null>(null);
  readonly status = signal<DataStepRunStatus | null>(null);

  /** Rows done over the estimate, 0 to 100; `null` without an estimate. */
  readonly percent = computed(() => {
    const s = this.status();
    const total = s?.rows_total ?? 0;
    if (!s || total <= 0) return null;
    return Math.min(100, Math.round((s.rows_scanned / total) * 100));
  });

  /** Minutes left, rounded up; `null` when the server gives no ETA. */
  readonly etaMinutes = computed(() => {
    const eta = this.status()?.eta_secs;
    return eta === null || eta === undefined ? null : Math.ceil(eta / 60);
  });

  readonly live = computed(() => LIVE.includes(this.status()?.status ?? ''));
  readonly canPause = computed(() => ['queued', 'claimed', 'running'].includes(this.status()?.status ?? ''));
  readonly canResume = computed(() => this.status()?.status === 'paused');
  readonly canAbandon = computed(() => {
    const s = this.status();
    return s === null || s.status === 'failed';
  });

  ngOnInit(): void {
    interval(POLL_MS).pipe(
      startWith(0),
      switchMap(() => this.svc.runStatus(this.runId()).pipe(catchError(() => of(null)))),
      takeWhile(s => s === null || LIVE.includes(s.status), true),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe(s => { if (s) this.status.set(s); });
  }

  pause(): void { this.control('pause'); }
  resume(): void { this.control('resume'); }

  async cancel(): Promise<void> {
    if (this.busy()) return;
    const ok = await this.confirm.confirm({
      title: this.lang.translate('fieldChange.run.cancelTitle'),
      message: this.lang.translate('fieldChange.run.cancelConfirm'),
      confirmText: this.lang.translate('fieldChange.run.cancel'),
      cancelText: this.lang.translate('fieldChange.dialog.cancel'),
      variant: 'warning',
    });
    if (!ok) return;
    this.control('cancel');
  }

  private control(action: 'pause' | 'resume' | 'cancel'): void {
    this.busy.set(true);
    this.error.set(null);
    this.svc.controlRun(this.runId(), action).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: s => { this.busy.set(false); this.status.set(s); },
      error: (err: ApiError) => { this.busy.set(false); this.error.set(structureErrorText(this.lang, err)); },
    });
  }

  async abandon(): Promise<void> {
    if (this.busy()) return;
    const ok = await this.confirm.confirm({
      title: this.lang.translate('fieldChange.run.abandonTitle'),
      message: this.lang.translate('fieldChange.run.abandonConfirm'),
      confirmText: this.lang.translate('fieldChange.run.abandon'),
      cancelText: this.lang.translate('fieldChange.dialog.cancel'),
      variant: 'warning',
    });
    if (!ok) return;
    this.busy.set(true);
    this.error.set(null);
    this.svc.abandonRun(this.entityId(), this.fieldId(), this.runId())
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: res => {
          this.busy.set(false);
          this.outcome.set(res);
          this.abandoned.emit(res);
        },
        error: (err: ApiError) => {
          this.busy.set(false);
          this.error.set(structureErrorText(this.lang, err));
        },
      });
  }
}
