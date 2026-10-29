import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { of } from 'rxjs';
import { describe, expect, it } from 'vitest';
import { LangService } from '@attome/base';
import { DashboardService, MetricCatalogueItem } from '@attome/xrm/dashboard/data';
import { MetricCatalogueComponent, filterMetrics } from './metric-catalogue.component';

function metric(over: Partial<MetricCatalogueItem> = {}): MetricCatalogueItem {
  return {
    id: 'm1', name: 'Win rate', key: 'win_rate', source_kind: 'query', period: 'month', unit: '%',
    certified: false, steward_ref: null, review_due: null, definition_version: 1, used_in: 0,
    ...over,
  };
}

describe('metric catalogue (P9-T15)', () => {
  it('searches by name or key, ignoring case', () => {
    const items = [metric(), metric({ id: 'm2', name: 'Pipeline', key: 'open_pipeline' })];
    expect(filterMetrics(items, 'WIN').map(m => m.id)).toEqual(['m1']);
    expect(filterMetrics(items, 'open_').map(m => m.id)).toEqual(['m2']);
    expect(filterMetrics(items, '  ').length).toBe(2);
  });

  it('shows a certification badge on a certified metric', () => {
    TestBed.configureTestingModule({
      imports: [MetricCatalogueComponent],
      providers: [
        {
          provide: DashboardService,
          useValue: {
            listMetrics: () => of({
              items: [metric({ certified: true, used_in: 2 }), metric({ id: 'm2', name: 'Pipeline', key: 'pipeline' })],
              total: 2, page: 1, page_size: 200,
            }),
          },
        },
        { provide: LangService, useValue: { translate: (key: string) => key, current: signal('en'), isRtl: () => false } },
      ],
    });
    const fixture = TestBed.createComponent(MetricCatalogueComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('[data-testid="catalogue-row"]').length).toBe(2);
    expect(el.querySelectorAll('[data-testid="certified-badge"]').length).toBe(1);
  });
});
