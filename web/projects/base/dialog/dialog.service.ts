import { Injectable, inject, signal } from '@angular/core';
import { ConfirmOptions, DialogState, ErrorDialogOptions, PromptOptions } from './dialog.types';

@Injectable({ providedIn: 'root' })
export class DialogService {
  private readonly stateSignal = signal<DialogState>(null);
  readonly state = this.stateSignal.asReadonly();

  confirm(options: ConfirmOptions): Promise<boolean> {
    return new Promise<boolean>(resolve => {
      this.settleDisplaced();
      this.stateSignal.set({
        kind: 'confirm',
        options,
        resolve: (result: boolean) => {
          this.stateSignal.set(null);
          resolve(result);
        },
      });
    });
  }

  prompt(options: PromptOptions): Promise<string | null> {
    return new Promise<string | null>(resolve => {
      this.settleDisplaced();
      this.stateSignal.set({
        kind: 'prompt',
        options,
        resolve: (result: string | null) => {
          this.stateSignal.set(null);
          resolve(result);
        },
      });
    });
  }

  error(options: ErrorDialogOptions | string): Promise<void> {
    const opts: ErrorDialogOptions = typeof options === 'string'
      ? { message: options }
      : options;

    return new Promise<void>(resolve => {
      this.settleDisplaced();
      this.stateSignal.set({
        kind: 'error',
        options: opts,
        resolve: () => {
          this.stateSignal.set(null);
          resolve();
        },
      });
    });
  }

  /**
   * NGB-F14. Opening a dialog over one that is still open must settle the
   * displaced one first: `confirm` resolves `false`, `prompt` resolves
   * `null`, and `error` resolves (its caller has nothing to decide). Without
   * this, a guarded action that awaits the first dialog waits forever — the
   * promise is orphaned, not rejected, so nothing surfaces.
   */
  private settleDisplaced(): void {
    const current = this.stateSignal();
    if (!current) return;
    this.stateSignal.set(null);
    if (current.kind === 'confirm') current.resolve(false);
    else if (current.kind === 'prompt') current.resolve(null);
    else current.resolve();
  }

  close(): void {
    const current = this.stateSignal();
    if (!current) return;
    if (current.kind === 'confirm') {
      current.resolve(false);
    } else if (current.kind === 'prompt') {
      current.resolve(null);
    } else if (current.kind === 'error') {
      current.resolve();
    }
  }
}

/**
 * Convenient alias service specifically for standard confirmation dialogs.
 */
@Injectable({ providedIn: 'root' })
export class ConfirmService {
  private readonly dialogService = inject(DialogService);

  confirm(options: ConfirmOptions): Promise<boolean> {
    return this.dialogService.confirm(options);
  }
}
