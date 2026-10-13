import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import { FieldChangeService } from '@attome/xrm/core/admin/data';
import { FieldRunStatusComponent } from './field-run-status.component';

describe('FieldRunStatusComponent', () => {
  let fixture: ComponentFixture<FieldRunStatusComponent>;
  let svc: { abandonRun: ReturnType<typeof vi.fn> };
  let confirm: { confirm: ReturnType<typeof vi.fn> };

  async function render() {
    await TestBed.configureTestingModule({
      imports: [FieldRunStatusComponent],
      providers: [
        { provide: FieldChangeService, useValue: svc },
        { provide: ConfirmService, useValue: confirm },
        { provide: LangService, useValue: { translate: (key: string) => (key.startsWith('structureErrors.') ? `T:${key}` : key), errorText: () => 'errors.unknown' } },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FieldRunStatusComponent);
    fixture.componentRef.setInput('entityId', 'e1');
    fixture.componentRef.setInput('fieldId', 'f1');
    fixture.componentRef.setInput('runId', 'run1');
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      abandonRun: vi.fn().mockReturnValue(of({
        run_id: 'run1', kind: 'retype', status: 'abandoned', shadow_dropped: true,
        archive_rows_removed: 2, conversion_completed: false, labels: [],
      })),
    };
    confirm = { confirm: vi.fn().mockResolvedValue(true) };
  });

  it('shows the run and abandons it after confirmation', async () => {
    await render();
    expect(el().textContent).toContain('fieldChange.run.running');
    await fixture.componentInstance.abandon();
    fixture.detectChanges();
    expect(svc.abandonRun).toHaveBeenCalledWith('e1', 'f1', 'run1');
    expect(el().querySelector('[data-testid="abandoned"]')).not.toBeNull();
    expect(el().textContent).toContain('fieldChange.run.shadowDropped');
  });

  it('does nothing when the confirmation is cancelled', async () => {
    confirm.confirm.mockResolvedValue(false);
    await render();
    await fixture.componentInstance.abandon();
    expect(svc.abandonRun).not.toHaveBeenCalled();
  });

  it('explains run_not_failed', async () => {
    svc.abandonRun.mockReturnValue(throwError(() => ({
      kind: 'conflict', status: 409, message: 'conflict: run_not_failed: only a failed run can be abandoned',
    })));
    await render();
    await fixture.componentInstance.abandon();
    fixture.detectChanges();
    expect(el().querySelector('[data-testid="run-error"]')?.textContent).toContain('structureErrors.run_not_failed');
  });
});
