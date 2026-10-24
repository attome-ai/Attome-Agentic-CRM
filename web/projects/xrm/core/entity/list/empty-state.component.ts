import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import { TranslatePipe } from '@attome/base';

/** Why a list is empty, which decides what the empty state offers. */
export type EmptyReason = 'filtered' | 'none';

/**
 * AK4-T1: what an empty list says, with one first action. A filtered list
 * that matched nothing offers to clear its filters; a list with no records
 * yet offers to create the first one when the caller may create.
 */
@Component({
  selector: 'xrm-empty-state',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <div class="es" data-testid="empty-state" [attr.data-reason]="reason()">
      <p class="es-title">{{ titleKey() | translate }}</p>
      <p class="es-hint">{{ hintKey() | translate }}</p>
      @if (reason() === 'filtered') {
        <button type="button" class="btn btn-secondary" data-empty-action="clear" (click)="clearFilters.emit()">
          {{ 'emptyState.clearFilters' | translate }}
        </button>
      } @else if (canCreate()) {
        <button type="button" class="btn btn-primary" data-empty-action="create" (click)="create.emit()">
          {{ 'emptyState.createFirst' | translate }}
        </button>
      }
    </div>
  `,
  styles: [`
    .es { display: flex; flex-direction: column; align-items: center; gap: 8px; padding-block: 2.5rem; padding-inline: 1rem; text-align: center; }
    .es-title { margin: 0; font-weight: 600; color: var(--color-text-primary); }
    .es-hint { margin: 0; color: var(--color-text-secondary); }
  `],
})
export class EmptyStateComponent {
  readonly reason = input<EmptyReason>('none');
  readonly canCreate = input(false);
  readonly create = output<void>();
  readonly clearFilters = output<void>();

  readonly titleKey = computed(() =>
    this.reason() === 'filtered' ? 'emptyState.filteredTitle' : 'emptyState.noneTitle');
  readonly hintKey = computed(() => {
    if (this.reason() === 'filtered') return 'emptyState.filteredHint';
    return this.canCreate() ? 'emptyState.noneHintCreate' : 'emptyState.noneHint';
  });
}
