import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fixtureDeployment } from '../data/fleet-fixtures';
import { FleetDeploymentDetailComponent } from './fleet-deployment-detail.component';

describe('FleetDeploymentDetailComponent', () => {
  let fixture: ComponentFixture<FleetDeploymentDetailComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  const withLedger = fixtureDeployment('d1', {
    maintenance_window: 'Fri 22:00',
    observation: {
      ...fixtureDeployment('d1').observation!,
      error_code: 'timeout',
      ledger_head: [{ layer: 'platform', scope: 'platform', changeset_id: 'c1', seq: 7, status: 'applied' }],
    },
    drift: { status: 'diverged', fields: ['application_version'], unconfirmed: ['image_digest'] },
  });

  async function render() {
    await TestBed.configureTestingModule({
      imports: [FleetDeploymentDetailComponent],
      providers: [
        provideRouter([]),
        { provide: FleetService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, errorText: () => 'errors.unknown', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FleetDeploymentDetailComponent);
    fixture.componentRef.setInput('id', 'd1');
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      getDeployment: vi.fn().mockReturnValue(of(withLedger)),
      listActions: vi.fn().mockReturnValue(of({
        items: [{
          id: 'a1', actor_ref: 'u1', deployment_ref: 'd1', rollout_ref: null, action: 'sync',
          remote_method: 'GET', remote_path: '/api/v1/admin/metadata/rollout/status', remote_status: 200,
          outcome: 'ok', detail: {}, created_at: '2026-10-01T10:00:00Z',
        }],
        total: 1, page: 1, page_size: 20,
      })),
      syncDeployment: vi.fn().mockReturnValue(of(fixtureDeployment('d1'))),
      updateDeployment: vi.fn().mockReturnValue(of(fixtureDeployment('d1', { label: 'Renamed', row_version: 2 }))),
      setCredential: vi.fn().mockReturnValue(of(fixtureDeployment('d1', { row_version: 2 }))),
    };
  });

  it('shows the check, the ledger head, drift and the action log', async () => {
    await render();
    expect(svc['getDeployment']).toHaveBeenCalledWith('d1');
    expect(svc['listActions']).toHaveBeenCalledWith('d1', 1, 20);
    const text = el().textContent ?? '';
    expect(text).toContain('timeout');
    expect(text).toContain('c1');
    expect(text).toContain('fleet.drift.status.diverged');
    expect(text).toContain('fleet.drift.field.application_version');
    expect(text).toContain('/api/v1/admin/metadata/rollout/status');
  });

  it('sends only the changed fields with the row_version', async () => {
    await render();
    const c = fixture.componentInstance;
    c.openEdit();
    c.editLabel.set('Renamed');
    c.editWindow.set('');
    c.saveEdit();
    expect(svc['updateDeployment']).toHaveBeenCalledWith('d1', { row_version: 1, label: 'Renamed', maintenance_window: '' });
    expect(c.panel()).toBe('none');
    expect(c.deployment()?.label).toBe('Renamed');
  });

  it('keeps the form open and reloads on a version conflict', async () => {
    svc['updateDeployment'].mockReturnValue(throwError(() => ({ kind: 'version_conflict', status: 409, message: '' })));
    await render();
    const c = fixture.componentInstance;
    c.openEdit();
    c.editLabel.set('Other');
    c.saveEdit();
    expect(c.panel()).toBe('edit');
    expect(c.formError()).toBe('fleet.detail.versionConflict');
    expect(svc['getDeployment']).toHaveBeenCalledTimes(2);
  });

  it('sets the credential with verify on, then forgets the secret', async () => {
    await render();
    const c = fixture.componentInstance;
    c.openCredential();
    expect(c.clientId()).toBe('client');
    c.secret.set('new-secret');
    c.saveCredential();
    expect(svc['setCredential']).toHaveBeenCalledWith(
      'd1', 1, { s2s_client_id: 'client', s2s_key_id: 'key', secret: 'new-secret' }, true);
    expect(c.secret()).toBe('');
    expect(c.notice()).toBe('fleet.detail.savedCredential');
  });

  it('shows a refused credential as the console\'s own message', async () => {
    svc['setCredential'].mockReturnValue(throwError(() => ({
      kind: 'validation', status: 422, code: 'validation_error',
      message: 'validation error: credential_refused: the customer server refused a call',
    })));
    await render();
    const c = fixture.componentInstance;
    c.openCredential();
    c.secret.set('wrong');
    c.saveCredential();
    expect(c.formError()).toBe('fleet.errors.credential_refused');
  });
});
