import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Router, provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fixtureDeployment as deployment } from '../data/fleet-fixtures';
import { FleetDeploymentsComponent } from './fleet-deployments.component';

describe('FleetDeploymentsComponent', () => {
  let fixture: ComponentFixture<FleetDeploymentsComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  async function render() {
    await TestBed.configureTestingModule({
      imports: [FleetDeploymentsComponent],
      providers: [
        provideRouter([]),
        { provide: FleetService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, errorText: () => 'errors.unknown', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FleetDeploymentsComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      listDeployments: vi.fn().mockReturnValue(of({
        items: [deployment('d1'), deployment('d2', { drift: { status: 'diverged', fields: ['schema_version'], unconfirmed: [] } })],
        total: 60, page: 1, page_size: 25,
      })),
      syncAll: vi.fn().mockReturnValue(of({ queued: true })),
      syncDeployment: vi.fn().mockReturnValue(of(deployment('d1', { label: 'Synced' }))),
      registerDeployment: vi.fn().mockReturnValue(of(deployment('d9'))),
    };
  });

  it('lists the first page with drift and links to each deployment', async () => {
    await render();
    expect(svc['listDeployments']).toHaveBeenCalledWith(false, 1, 25);
    expect(el().querySelectorAll('tbody tr').length).toBe(2);
    expect(el().textContent).toContain('fleet.drift.status.diverged');
    expect(el().textContent).toContain('fleet.drift.field.schema_version');
    const link = el().querySelector('tbody a') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/xrm/fleet/deployments/d1');
  });

  it('pages one-based and re-reads with the inactive filter from page 1', async () => {
    await render();
    fixture.componentInstance.next();
    expect(svc['listDeployments']).toHaveBeenLastCalledWith(false, 2, 25);
    fixture.componentInstance.toggleInactive(true);
    expect(svc['listDeployments']).toHaveBeenLastCalledWith(true, 1, 25);
  });

  it('queues a sync of every deployment and says so', async () => {
    await render();
    fixture.componentInstance.syncAll();
    fixture.detectChanges();
    expect(svc['syncAll']).toHaveBeenCalled();
    expect(el().querySelector('[role="status"]')?.textContent).toContain('fleet.deployments.syncQueued');
  });

  it('syncs one deployment and shows its new check in place', async () => {
    await render();
    fixture.componentInstance.syncOne(fixture.componentInstance.deployments()[0]);
    fixture.detectChanges();
    expect(svc['syncDeployment']).toHaveBeenCalledWith('d1');
    expect(el().textContent).toContain('Synced');
  });

  it('registers with the credential only when asked, then opens the new deployment', async () => {
    await render();
    const router = TestBed.inject(Router);
    const navigate = vi.spyOn(router, 'navigate').mockResolvedValue(true);
    const c = fixture.componentInstance;
    c.openForm();
    c.projectCode.set('bmd');
    c.label.set('BMD production');
    c.baseUrl.set('https://bmd.example');
    expect(c.canRegister()).toBe(true);
    c.withCredential.set(true);
    expect(c.canRegister()).toBe(false);
    c.clientId.set('client');
    c.keyId.set('key');
    c.secret.set('s3cret');
    c.register();
    expect(svc['registerDeployment']).toHaveBeenCalledWith(expect.objectContaining({
      project_code: 'bmd', environment: 'prod', ring: 'broad', maintenance_window: null,
      credential: { s2s_client_id: 'client', s2s_key_id: 'key', secret: 's3cret' },
    }));
    expect(c.secret()).toBe('');
    expect(navigate).toHaveBeenCalledWith(['/xrm/fleet/deployments', 'd9']);
  });

  it('shows a load failure as an alert', async () => {
    svc['listDeployments'].mockReturnValue(throwError(() => ({ kind: 'forbidden', status: 403, message: '', code: 'fleet_console_loopback_only' })));
    await render();
    expect(el().querySelector('[role="alert"]')?.textContent).toContain('fleet.errors.loopbackOnly');
  });
});
