import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { OpsMetricsComponent, polyline } from './metrics.component';

describe('OpsMetricsComponent (U4-T4)', () => {
  it('lists metric names and draws the chosen one', () => {
    const get = vi.fn((path: string) => {
      if (path.endsWith('/names')) return of({ items: ['pool_size', 'http_requests_total'] });
      if (path.endsWith('/catalogue')) {
        return of({ items: [{ name: 'pool_size', kind: 'gauge', unit: 'connections', en: 'Pool size.', ar: 'حجم المجمع.' }] });
      }
      return of({ items: [{ at: '2026-10-14T10:00:00Z', value: 1 }, { at: '2026-10-14T10:01:00Z', value: 3 }] });
    });
    TestBed.configureTestingModule({
      imports: [OpsMetricsComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (key: string) => key, current: () => 'en' } },
      ],
    });
    const fixture = TestBed.createComponent(OpsMetricsComponent);
    fixture.detectChanges();
    expect(fixture.componentInstance.names()).toEqual(['pool_size', 'http_requests_total']);
    fixture.componentInstance.choose('pool_size');
    fixture.detectChanges();
    const [path, params] = get.mock.calls[2] as unknown as [string, Record<string, string>];
    expect(path).toBe('/api/v1/admin/ops/metrics/query');
    expect(params['name']).toBe('pool_size');
    expect(params['step']).toBe('60');
    expect(fixture.nativeElement.querySelector('[data-chart] polyline')).not.toBeNull();
    expect(fixture.nativeElement.querySelector('[data-summary]')?.textContent).toContain('max 3');
    expect(fixture.nativeElement.querySelector('[data-meaning]')?.textContent).toContain('Pool size. (connections)');
  });

  it('scales points into the box', () => {
    expect(polyline([], 100, 50)).toBe('');
    expect(polyline([
      { at: '2026-10-14T10:00:00Z', value: 0 },
      { at: '2026-10-14T10:01:00Z', value: 10 },
    ], 100, 50)).toBe('0.0,50.0 100.0,0.0');
  });
});
