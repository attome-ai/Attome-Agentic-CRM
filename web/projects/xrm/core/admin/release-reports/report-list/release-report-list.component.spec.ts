import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ReleaseReportService } from '@attome/xrm/core/admin/data';
import { ReleaseReportListComponent } from './release-report-list.component';

describe('ReleaseReportListComponent', () => {
  let fixture: ComponentFixture<ReleaseReportListComponent>;
  let svc: { listReports: ReturnType<typeof vi.fn>; summary: ReturnType<typeof vi.fn> };

  const report = (id: string, open: number) => ({
    id, apply_ids: [], release: 'v1.2.0: 0042-contract', source: 'boot', status: 'ready',
    items_total: 3, items_open: open, backup_ref: null, backup_retain_until: null,
    created_at: '2026-10-01T10:00:00Z', ready_at: '2026-10-01T10:05:00Z', notified_at: null, row_version: 0,
  });

  async function render() {
    await TestBed.configureTestingModule({
      imports: [ReleaseReportListComponent],
      providers: [
        provideRouter([]),
        { provide: ReleaseReportService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, errorText: () => 'errors.unknown', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(ReleaseReportListComponent);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      listReports: vi.fn().mockReturnValue(of({ items: [report('r1', 2), report('r2', 0)], total: 45, page: 1, page_size: 20 })),
      summary: vi.fn().mockReturnValue(of({ open_items: 2, by_kind: { conflict: 2 }, last_release_at: null, building: 0 })),
    };
  });

  it('loads the first page and the summary', async () => {
    await render();
    expect(svc.listReports).toHaveBeenCalledWith({ status: undefined, source: undefined }, 1, 20);
    expect(el().querySelectorAll('tbody tr').length).toBe(2);
    expect(el().querySelector('[data-testid="summary"]')?.textContent).toContain('releaseReport.kinds.conflict');
    const link = el().querySelector('tbody a') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/xrm/admin/release-reports/r1');
  });

  it('pages one-based', async () => {
    await render();
    fixture.componentInstance.next();
    expect(svc.listReports).toHaveBeenLastCalledWith({ status: undefined, source: undefined }, 2, 20);
    expect(fixture.componentInstance.pages()).toBe(3);
  });

  it('applies the filters from page 1', async () => {
    await render();
    fixture.componentInstance.page.set(3);
    fixture.componentInstance.status.set('ready');
    fixture.componentInstance.source.set('boot');
    fixture.componentInstance.apply();
    expect(svc.listReports).toHaveBeenLastCalledWith({ status: 'ready', source: 'boot' }, 1, 20);
  });

  it('shows the error when the list fails, and still renders without a summary', async () => {
    svc.listReports.mockReturnValue(throwError(() => ({ kind: 'forbidden', status: 403, message: '' })));
    svc.summary.mockReturnValue(throwError(() => ({ kind: 'forbidden', status: 403, message: '' })));
    await render();
    expect(el().querySelector('[role="alert"]')?.textContent).toContain('errors.unknown');
    expect(el().querySelector('[data-testid="summary"]')).toBeNull();
  });
});
