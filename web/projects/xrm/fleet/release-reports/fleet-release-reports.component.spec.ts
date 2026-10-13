import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fixtureDeployment, fixtureItem } from '../data/fleet-fixtures';
import { FleetReleaseReportsComponent } from './fleet-release-reports.component';

describe('FleetReleaseReportsComponent', () => {
  let fixture: ComponentFixture<FleetReleaseReportsComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  const report = {
    id: 'r1', apply_ids: [], release: 'v1.2.0', source: 'admin', status: 'ready', items_total: 3,
    items_open: 2, backup_ref: null, backup_retain_until: null, created_at: '2026-10-01T10:00:00Z',
    ready_at: null, notified_at: null, row_version: 0,
  };

  async function render(deployment?: string) {
    await TestBed.configureTestingModule({
      imports: [FleetReleaseReportsComponent],
      providers: [
        provideRouter([]),
        { provide: FleetService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, errorText: () => 'errors.unknown', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FleetReleaseReportsComponent);
    if (deployment) fixture.componentRef.setInput('deployment', deployment);
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      openItems: vi.fn().mockReturnValue(of({
        items: [
          { deployment_id: 'd1', deployment_label: 'BMD prod', project_code: 'BMD', report_id: 'r1', item: fixtureItem('i1') },
          {
            deployment_id: 'd2', deployment_label: 'ACM prod', project_code: 'ACM', report_id: 'r9',
            item: fixtureItem('i2', { values: null, values_hidden: true }),
          },
        ],
        total: 2, page: 1, page_size: 25,
      })),
      allDeployments: vi.fn().mockReturnValue(of([fixtureDeployment('d1'), fixtureDeployment('d3', { has_credential: false })])),
      listReports: vi.fn().mockReturnValue(of({ items: [report], total: 1, page: 1, page_size: 20 })),
      listItems: vi.fn().mockReturnValue(of({ items: [fixtureItem('i5', { record_id: null })], total: 1, page: 1, page_size: 25 })),
      decideItem: vi.fn().mockReturnValue(of({ ...fixtureItem('i1'), status: 'accepted', values: undefined })),
    };
  });

  it('lists the fleet\'s open items with the customer\'s values, and says when values are hidden', async () => {
    await render();
    expect(svc['openItems']).toHaveBeenCalledWith(1, 25);
    const text = el().textContent ?? '';
    expect(text).toContain('BMD prod');
    expect(text).toContain('a@customer.example');
    expect(text).toContain('fleet.reports.valuesHidden');
  });

  it('offers only customers with a credential', async () => {
    await render();
    expect(fixture.componentInstance.readable().map(d => d.id)).toEqual(['d1']);
  });

  it('accepts with the item row_version and keeps the values on screen', async () => {
    await render();
    const c = fixture.componentInstance;
    c.decide('d1', c.openItems()[0].item, 'accept');
    expect(svc['decideItem']).toHaveBeenCalledWith('d1', 'i1', 'accept', 3, null);
    expect(c.openItems()[0].item.status).toBe('accepted');
    expect(c.openItems()[0].item.values?.ours).toBe('b@example');
    expect(c.notice()).toBe('fleet.reports.decided');
  });

  it('needs the record version before Use mine on a record conflict', async () => {
    await render();
    const c = fixture.componentInstance;
    const item = c.openItems()[0].item;
    expect(c.needsRecordVersion(item)).toBe(true);
    expect(c.useMineReady(item)).toBe(false);
    c.decide('d1', item, 'use-mine');
    expect(svc['decideItem']).not.toHaveBeenCalled();
    c.setRecordVersion('i1', '12');
    c.decide('d1', item, 'use-mine');
    expect(svc['decideItem']).toHaveBeenCalledWith('d1', 'i1', 'use-mine', 3, 12);
  });

  it('opens one customer from ?deployment= and reads a report\'s open items', async () => {
    await render('d1');
    const c = fixture.componentInstance;
    expect(svc['listReports']).toHaveBeenCalledWith('d1', null, 1, 20);
    c.openReport(c.reports()[0]);
    expect(svc['listItems']).toHaveBeenCalledWith('d1', 'r1', { status: 'open', kind: undefined }, 1, 25);
    // A rule conflict (no record) can use mine without a record version.
    expect(c.useMineReady(c.items()[0])).toBe(true);
  });

  it('shows a customer refusal next to the item', async () => {
    svc['decideItem'].mockReturnValue(throwError(() => ({
      kind: 'unknown', status: 502, code: 'fleet_remote_error', message: 'the customer server refused or failed: remote_error',
    })));
    await render();
    const c = fixture.componentInstance;
    c.decide('d1', c.openItems()[0].item, 'dismiss');
    expect(c.itemError('i1')).toContain('fleet.errors.remote');
    expect(c.busyItem()).toBeNull();
  });
});
