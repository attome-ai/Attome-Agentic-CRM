import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { FleetService } from '../data/fleet.service';
import { fixtureRollout, fixtureTarget } from '../data/fleet-fixtures';
import { FleetRolloutDetailComponent, groupTargets, safeApprovalUrl } from './fleet-rollout-detail.component';

describe('FleetRolloutDetailComponent', () => {
  let fixture: ComponentFixture<FleetRolloutDetailComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;
  let confirm: ReturnType<typeof vi.fn>;

  async function render() {
    await TestBed.configureTestingModule({
      imports: [FleetRolloutDetailComponent],
      providers: [
        provideRouter([]),
        { provide: FleetService, useValue: svc },
        { provide: DialogService, useValue: { confirm } },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, errorText: () => 'errors.unknown', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FleetRolloutDetailComponent);
    fixture.componentRef.setInput('id', 'ro1');
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    confirm = vi.fn().mockResolvedValue(true);
    const pending = fixtureTarget('t2', {
      deployment_id: 'd2', deployment_label: 'Customer d2', environment: 'test', status: 'approval_pending',
      approval_url: 'https://acm.example/xrm/admin/approvals', remote_approval_id: 'ap1', maintenance_window: null,
    });
    svc = {
      getRollout: vi.fn().mockReturnValue(of(fixtureRollout('in_progress', [fixtureTarget('t1'), pending]))),
      applyTarget: vi.fn().mockReturnValue(of(fixtureTarget('t1', { status: 'approval_pending', row_version: 2 }))),
      skipTarget: vi.fn().mockReturnValue(of(fixtureTarget('t1', { status: 'skipped' }))),
      haltRollout: vi.fn().mockReturnValue(of(fixtureRollout('halted'))),
      resumeRollout: vi.fn().mockReturnValue(of(fixtureRollout('in_progress'))),
      cancelRollout: vi.fn().mockReturnValue(of(fixtureRollout('cancelled'))),
      refreshRollout: vi.fn().mockReturnValue(of({ queued: 1 })),
    };
  });

  it('groups targets under their wave and offers the customer\'s approval page, never an approve button', async () => {
    await render();
    expect(groupTargets(fixture.componentInstance.detail()!)[0].targets.length).toBe(2);
    const link = el().querySelector('a[target="_blank"]') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('https://acm.example/xrm/admin/approvals');
    expect(link.getAttribute('rel')).toBe('noopener noreferrer');
    expect(el().textContent).not.toContain('fleet.rollout.approve ');
    expect(el().textContent).toContain('fleet.rollout.neverApproves');
  });

  it('refuses a non-http approval link', () => {
    expect(safeApprovalUrl('javascript:alert(1)')).toBeNull();
    expect(safeApprovalUrl('http://127.0.0.1:7865/xrm/admin/approvals')).not.toBeNull();
  });

  it('needs the backup reference before applying a production customer', async () => {
    await render();
    const c = fixture.componentInstance;
    const target = c.detail()!.targets[0];
    expect(c.canApply(target)).toBe(true);
    expect(c.applyReady(target)).toBe(false);
    c.apply(target);
    expect(svc['applyTarget']).not.toHaveBeenCalled();
    c.setBackupRef('t1', ' backup-2026-10-01 ');
    c.apply(target);
    expect(svc['applyTarget']).toHaveBeenCalledWith('ro1', 't1', { row_version: 1, backup_ref: 'backup-2026-10-01' });
    expect(c.detail()!.targets[0].status).toBe('approval_pending');
    expect(c.notice()).toBe('fleet.rollout.sentForApproval');
  });

  it('applies only a planned customer of the current wave of a running rollout', async () => {
    await render();
    const c = fixture.componentInstance;
    expect(c.canApply(c.detail()!.targets[1])).toBe(false);
    c.detail.set(fixtureRollout('halted'));
    expect(c.canApply(c.detail()!.targets[0])).toBe(false);
  });

  it('halts and resumes with the rollout row_version', async () => {
    await render();
    const c = fixture.componentInstance;
    c.halt();
    expect(svc['haltRollout']).toHaveBeenCalledWith('ro1', 4);
    expect(c.status()).toBe('halted');
    c.resume();
    expect(svc['resumeRollout']).toHaveBeenCalledWith('ro1', 4);
    expect(c.status()).toBe('in_progress');
  });

  it('cancels only after confirming', async () => {
    await render();
    const c = fixture.componentInstance;
    confirm.mockResolvedValueOnce(false);
    await c.cancel();
    expect(svc['cancelRollout']).not.toHaveBeenCalled();
    await c.cancel();
    expect(svc['cancelRollout']).toHaveBeenCalledWith('ro1', 4);
    expect(c.status()).toBe('cancelled');
  });

  it('skips a customer after confirming and re-reads the rollout', async () => {
    await render();
    const c = fixture.componentInstance;
    await c.skip(c.detail()!.targets[0]);
    expect(svc['skipTarget']).toHaveBeenCalledWith('ro1', 't1', 1);
    expect(svc['getRollout']).toHaveBeenCalledTimes(2);
  });

  it('re-queues waiting steps and says how many', async () => {
    await render();
    fixture.componentInstance.refreshSteps();
    expect(svc['refreshRollout']).toHaveBeenCalledWith('ro1');
    expect(fixture.componentInstance.notice()).toBe('fleet.rollout.stepsQueued');
  });

  it('shows a refused apply next to the customer', async () => {
    svc['applyTarget'].mockReturnValue(throwError(() => ({
      kind: 'conflict', status: 409, code: 'conflict', message: 'conflict: fleet_target_not_planned: only a planned target',
    })));
    await render();
    const c = fixture.componentInstance;
    c.setBackupRef('t1', 'b1');
    c.apply(c.detail()!.targets[0]);
    expect(c.targetError('t1')).toBe('fleet.errors.fleet_target_not_planned');
    expect(c.busyTarget()).toBeNull();
  });
});
