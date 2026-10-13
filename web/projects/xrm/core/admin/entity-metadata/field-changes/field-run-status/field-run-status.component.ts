import {
  ChangeDetectionStrategy, Component, DestroyRef, inject, input, output, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import { FieldChangeService, structureErrorText, type AbandonedFieldRun } from '@attome/xrm/core/admin/data';

/**
 * The background run of a field change on a large table (a type change's
 * `retype`, a delete's `archive` copy). There is no route that reads a run's
 * progress yet, so this says the work continues in the background and offers
 * **Abandon** for a run that failed (`POST …/runs/{run_id}/abandon`): it
 * drops a retype's unfinished shadow column and frees the field. The server
 * refuses a run that has not failed (`run_not_failed`).
 */
@Component({
  selector: 'attome-field-run-status',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../../../../../styles/admin-page.css', './field-run-status.component.css'],
  templateUrl: './field-run-status.component.html',
})
export class FieldRunStatusComponent {
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
