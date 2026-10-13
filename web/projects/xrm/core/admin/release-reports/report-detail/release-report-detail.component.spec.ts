import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ReleaseReportService, type ReportItemView } from '@attome/xrm/core/admin/data';
import { ReleaseReportDetailComponent } from './release-report-detail.component';

describe('ReleaseReportDetailComponent', () => {
  let fixture: ComponentFixture<ReleaseReportDetailComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  const report = {
    id: 'r1', apply_ids: [], release: 'v1.2.0: 0042-contract', source: 'boot', status: 'ready',
    items_total: 2, items_open: 1, backup_ref: null, backup_retain_until: null,
    created_at: '2026-10-01T10:00:00Z', ready_at: null, notified_at: null, row_version: 0,
  };
  const item = (id: string, over: Partial<ReportItemView> = {}): ReportItemView => ({
    id, report_ref: 'r1', kind: 'field_deleted', actionable: true, status: 'open',
    entity_logicalname: 'contact', field_logicalname: 'rating', record_id: null,
    object_kind: null, object_ref: null, detail: { archived: 4 }, has_values: false,
    changeset_id: null, op_seq: null, decided_by: null, decided_at: null, superseded_by: null,
    created_at: '2026-10-01T10:00:00Z', row_version: 0, values: null, values_hidden: false,
    ...over,
  });

  async function render() {
    await TestBed.configureTestingModule({
      imports: [ReleaseReportDetailComponent],
      providers: [
        provideRouter([]),
        { provide: ReleaseReportService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (key: string) => key, errorText: () => 'errors.unknown', intlLocale: () => 'en-US' },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(ReleaseReportDetailComponent);
    fixture.componentRef.setInput('id', 'r1');
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      getReport: vi.fn().mockReturnValue(of(report)),
      listItems: vi.fn().mockReturnValue(of({ items: [item('i1'), item('i2')], total: 2, page: 1, page_size: 25 })),
      accept: vi.fn(), dismiss: vi.fn(), useMine: vi.fn(), restore: vi.fn(), recordRowVersion: vi.fn(),
    };
  });

  it('loads the report and its open items, one-based', async () => {
    await render();
    expect(svc['getReport']).toHaveBeenCalledWith('r1');
    expect(svc['listItems']).toHaveBeenCalledWith('r1', { kind: undefined, status: 'open', entity: undefined }, 1, 25);
    expect(el().querySelector('[data-testid="report-head"]')?.textContent).toContain('v1.2.0');
    expect(el().querySelectorAll('attome-report-item').length).toBe(2);
  });

  it('applies kind, status and entity filters from page 1', async () => {
    await render();
    const cmp = fixture.componentInstance;
    cmp.page.set(2);
    cmp.kind.set('conflict');
    cmp.itemStatus.set('');
    cmp.entity.set(' contact ');
    cmp.apply();
    expect(svc['listItems']).toHaveBeenLastCalledWith('r1', { kind: 'conflict', status: undefined, entity: 'contact' }, 1, 25);
  });

  it('replaces a decided item in place and refreshes the counts', async () => {
    await render();
    fixture.componentInstance.onChanged(item('i1', { status: 'dismissed' }));
    expect(fixture.componentInstance.items()[0].status).toBe('dismissed');
    expect(svc['getReport']).toHaveBeenCalledTimes(2);
  });

  it('reloads and says why after a stale decision', async () => {
    await render();
    fixture.componentInstance.onStale();
    fixture.detectChanges();
    expect(svc['listItems']).toHaveBeenCalledTimes(2);
    expect(el().querySelector('[data-testid="notice"]')?.textContent).toContain('releaseReport.detail.reloaded');
  });

  it('reloads when the route reuses the page for another report', async () => {
    await render();
    fixture.componentRef.setInput('id', 'r2');
    fixture.detectChanges();
    expect(svc['getReport']).toHaveBeenLastCalledWith('r2');
    expect(svc['listItems']).toHaveBeenLastCalledWith('r2', expect.anything(), 1, 25);
  });

  it('says the report was not found', async () => {
    svc['getReport'] = vi.fn().mockReturnValue(throwError(() => ({ kind: 'not_found', status: 404, message: '' })));
    await render();
    expect(el().querySelector('[data-testid="report-error"]')?.textContent).toContain('releaseReport.detail.notFound');
  });
});
