import { ChangeDetectionStrategy, Component, inject, input, output, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { DuplicatesService } from '@attome/xrm/core/admin/data';

/**
 * A15-T10: the note after a merge, with Undo
 * (`POST /api/v1/{entity}/merges/{merge_id}/undo`). The server refuses the
 * undo once the survivor has changed since the merge (409); the bar then
 * says so instead of retrying.
 */
@Component({
  selector: 'xrm-merge-undo-bar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../../../styles/inline-actions.css'],
  template: `
    <div class="merge-undo" role="status" data-merge-undo>
      <i class="las la-check" aria-hidden="true"></i>
      <span>
        @if (error()) {
          {{ error() }}
        } @else {
          {{ 'mergeDialog.done' | translate }}
        }
      </span>
      @if (!error()) {
        <button type="button" class="btn-sm btn-sm-accent" data-merge-undo-button [disabled]="busy()" (click)="undo()">
          {{ (busy() ? 'mergeDialog.undoing' : 'mergeDialog.undo') | translate }}
        </button>
      }
      <button type="button" class="btn-sm btn-ghost" [attr.aria-label]="'duplicateBanner.close' | translate" (click)="closed.emit()">
        <i class="las la-times" aria-hidden="true"></i>
      </button>
    </div>
  `,
  styles: [`
    :host { display: block; margin-block-end: 16px; }
    .merge-undo {
      display: flex; align-items: center; gap: 10px; padding-block: 8px; padding-inline: 12px;
      border: 1px solid var(--color-border); border-inline-start: 3px solid var(--color-accent);
      border-radius: 8px; background: var(--color-bg-alt); color: var(--color-text-primary);
    }
    .merge-undo > span { flex: 1; }
  `],
})
export class MergeUndoBarComponent {
  private readonly svc = inject(DuplicatesService);
  private readonly lang = inject(LangService);

  readonly entity = input.required<string>();
  readonly mergeId = input.required<string>();
  readonly undone = output<void>();
  readonly closed = output<void>();

  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  undo(): void {
    this.busy.set(true);
    this.svc.undoMerge(this.entity(), this.mergeId()).subscribe({
      next: () => {
        this.busy.set(false);
        this.undone.emit();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.status === 409 ? this.lang.translate('mergeDialog.undoRefused') : this.lang.errorText(e));
      },
    });
  }
}
