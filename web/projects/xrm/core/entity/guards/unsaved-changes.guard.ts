import { inject } from '@angular/core';
import { CanDeactivateFn } from '@angular/router';
import { LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

/** A routed screen that can hold unsaved work opts into the leave guard by
 * exposing this. */
export interface HasUnsavedChanges {
  hasUnsavedChanges(): boolean;
}

/**
 * Dashboard 10/10 Phase 1.4 — asks before navigating away from a screen with
 * unsaved work. Generic: any routed component exposing `hasUnsavedChanges()`
 * is protected; any other component passes straight through. Covers in-app
 * navigation only — a component also listens for `beforeunload` itself to
 * cover a refresh or tab close.
 */
export const unsavedChangesGuard: CanDeactivateFn<Partial<HasUnsavedChanges>> = component => {
  if (!component?.hasUnsavedChanges?.()) return true;
  const dialog = inject(DialogService);
  const lang = inject(LangService);
  return dialog.confirm({ message: lang.translate('xrmForm.unsaved'), variant: 'warning' });
};
