import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { xrmEn } from '@attome/xrm/core/i18n-en';
import { EntityService } from '@attome/xrm/core/entity';
import { DashboardService, WidgetRecordsResponse } from '@attome/xrm/dashboard/data';
import { WidgetRecordsDrawerComponent } from './widget-records-drawer.component';

// Dashboard 10/10 Phase 3.1/3.4 — the drawer renders the server's records and
// context, pages with the keyset cursor, and exports with the drill's filters.

function page(rows: Record<string, unknown>[], cursor?: string, drillFilters: unknown[] | null = [
  { field: 'status', op: 'eq', value: 'won' },
]): WidgetRecordsResponse {
  return {
    widget_id: 'w1',
    drillability: 'exact',
    definition_source: 'published',
    definition_fingerprint: 'fp',
    timezone: 'UTC',
    timezone_source: 'utc',
    applied_filters: [{ filter: { field: 'status', op: 'eq', value: 'won' }, origin: { kind: 'parameter', name: 'stage' } }],
    records: {
      entity_logical_name: 'deal',
      columns: [{ name: 'id', data_type: 'lookup' }, { name: 'amount', data_type: 'number' }],
      rows,
      total: 3,
      as_of: '2026-09-17T10:00:00Z',
      next_cursor: cursor,
      drill_filters: drillFilters ?? undefined,
    },
  } as WidgetRecordsResponse;
}

function setup(responses: WidgetRecordsResponse[]) {
  const widgetRecords = vi.fn((_dashboard: string, _widget: string, _inputs: unknown) => of(responses.shift()!));
  const exportRecords = vi.fn(() => of({ id: 'e1', status: 'pending', matching_rows: 3 }));
  const navigateByUrl = vi.fn();
  TestBed.configureTestingModule({
    imports: [WidgetRecordsDrawerComponent],
    providers: [
      { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      provideAttomeI18n(), provideXrmI18n(xrmEn),
      { provide: Router, useValue: { navigateByUrl } },
      { provide: DashboardService, useValue: { widgetRecords } },
      { provide: EntityService, useValue: { exportRecords } },
    ],
  });
  const fixture = TestBed.createComponent(WidgetRecordsDrawerComponent);
  fixture.componentRef.setInput('dashboardId', 'd1');
  fixture.componentRef.setInput('widgetId', 'w1');
  fixture.componentRef.setInput('bucketKey', { kind: 'value', value: 'won' });
  fixture.componentRef.setInput('parameters', { stage: 'won' });
  fixture.detectChanges();
  return { fixture, widgetRecords, exportRecords, navigateByUrl };
}

describe('WidgetRecordsDrawerComponent', () => {
  it('asks for the bucket with the same values and shows the exact total and context', () => {
    const { fixture, widgetRecords } = setup([page([{ id: 'r1', amount: 5 }], 'r1')]);
    expect(widgetRecords).toHaveBeenCalledWith('d1', 'w1', expect.objectContaining({
      bucket_key: { kind: 'value', value: 'won' }, parameters: { stage: 'won' }, page_size: 50,
    }));
    const text = (fixture.nativeElement as HTMLElement).textContent ?? '';
    // Parameterised messages compile lazily; assert the server's exact total.
    expect(fixture.componentInstance.records()?.total).toBe(3);
    expect(text).toContain('status eq won');
    expect(text).toContain('parameter');
  });

  it('says when the number counts records the viewer cannot open (P7-T3), and never how many', () => {
    const hidden = { ...page([{ id: 'r1' }]), some_records_hidden: true } as WidgetRecordsResponse;
    const { fixture } = setup([hidden]);
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-hidden]')).not.toBeNull();
  });

  it('says nothing about hidden records when the viewer reads them all', () => {
    const { fixture } = setup([{ ...page([{ id: 'r1' }]), some_records_hidden: false } as WidgetRecordsResponse]);
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-hidden]')).toBeNull();
  });

  it('pages with the keyset cursor and appends rows', () => {
    const { fixture, widgetRecords } = setup([page([{ id: 'r1' }], 'r1'), page([{ id: 'r2' }])]);
    fixture.componentInstance.loadMore();
    expect(widgetRecords.mock.calls[1][2]).toEqual(expect.objectContaining({ after_id: 'r1' }));
    expect(fixture.componentInstance.rows().map(r => r['id'])).toEqual(['r1', 'r2']);
  });

  it("exports with the drill's exact filters and links each record", () => {
    const { fixture, exportRecords, navigateByUrl } = setup([page([{ id: 'r1' }])]);
    fixture.componentInstance.exportRecords('csv');
    expect(exportRecords).toHaveBeenCalledWith('deal', 'csv', [], [{ field: 'status', op: 'eq', value: 'won' }]);
    fixture.componentInstance.openRecord({ id: 'r1' });
    expect(navigateByUrl).toHaveBeenCalledWith(expect.stringContaining('/form?id=r1'));
  });

  it('offers no export for the Other bucket', () => {
    const { fixture } = setup([page([{ id: 'r1' }], undefined, null)]);
    expect((fixture.nativeElement as HTMLElement).textContent).not.toContain('Export CSV');
  });
});
