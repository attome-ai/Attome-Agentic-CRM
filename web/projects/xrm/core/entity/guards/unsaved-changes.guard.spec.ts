import { TestBed } from '@angular/core/testing';
import { ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { describe, expect, it, vi } from 'vitest';
import { unsavedChangesGuard } from './unsaved-changes.guard';

function runGuard(component: { hasUnsavedChanges?: () => boolean } | null, confirmResult: boolean) {
  const confirm = vi.fn(() => Promise.resolve(confirmResult));
  TestBed.configureTestingModule({
    providers: [
      { provide: DialogService, useValue: { confirm } },
      { provide: LangService, useValue: { translate: (key: string) => key } },
    ],
  });
  const result = TestBed.runInInjectionContext(() =>
    unsavedChangesGuard(
      component as never,
      {} as ActivatedRouteSnapshot,
      {} as RouterStateSnapshot,
      {} as RouterStateSnapshot,
    ));
  return { result, confirm };
}

describe('unsavedChangesGuard', () => {
  it('lets navigation through when nothing is unsaved, without asking', () => {
    const { result, confirm } = runGuard({ hasUnsavedChanges: () => false }, false);
    expect(result).toBe(true);
    expect(confirm).not.toHaveBeenCalled();
  });

  it('lets a component that does not opt in through', () => {
    const { result } = runGuard({}, false);
    expect(result).toBe(true);
  });

  it('blocks navigation while dirty when the user stays', async () => {
    const { result, confirm } = runGuard({ hasUnsavedChanges: () => true }, false);
    expect(confirm).toHaveBeenCalledOnce();
    expect(await result).toBe(false);
  });

  it('allows navigation while dirty when the user chooses to leave', async () => {
    const { result } = runGuard({ hasUnsavedChanges: () => true }, true);
    expect(await result).toBe(true);
  });
});
