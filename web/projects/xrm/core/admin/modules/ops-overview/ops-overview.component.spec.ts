import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { OpsOverviewComponent, areaOf } from './ops-overview.component';

describe('OpsOverviewComponent (U4-T4)', () => {
  function create() {
    const get = vi.fn((path: string) => {
      if (path.endsWith('/nodes')) {
        return of({ items: [
          { node: 'web-1:7865', version: '2.0.0', last_seen: '2026-10-15T08:00:00Z', healthy: true },
          { node: 'web-2:7865', version: '2.0.0', last_seen: '2026-10-15T07:00:00Z', healthy: false },
        ] });
      }
      if (path.endsWith('/catalogue')) {
        return of({ items: [
          { name: 'http_requests_total', kind: 'counter', unit: 'requests', en: 'Requests', ar: 'طلبات' },
          { name: 'apalis_pending_jobs', kind: 'gauge', unit: 'jobs', en: 'Pending jobs', ar: 'مهام' },
          { name: 'cache_hits_total', kind: 'counter', unit: 'hits', en: 'Hits', ar: 'إصابات' },
        ] });
      }
      if (path.endsWith('/names')) return of({ items: ['http_requests_total', 'apalis_pending_jobs'] });
      return of({ items: [{ at: '2026-10-15T08:00:00Z', value: 3 }, { at: '2026-10-15T08:01:00Z', value: 5 }] });
    });
    TestBed.configureTestingModule({
      imports: [OpsOverviewComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(OpsOverviewComponent);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('sorts metrics into pages by name', () => {
    expect(areaOf('http_request_duration_seconds')).toBe('requests');
    expect(areaOf('db_pool_connections')).toBe('database');
    expect(areaOf('apalis_pending_jobs')).toBe('jobs');
    expect(areaOf('attome_inference_requests_total')).toBe('models');
    expect(areaOf('ai_turns_total')).toBe('models');
    expect(areaOf('something_else')).toBe('other');
  });

  it('shows nodes by health and the sampled metrics of the chosen page', () => {
    const { fixture, get } = create();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('[data-node]').length).toBe(2);
    expect(el.querySelector('[data-node="web-2:7865"]')?.classList.contains('oo-down')).toBe(true);
    expect(el.querySelector('[data-chart="http_requests_total"]')?.textContent).toContain('5');
    expect(get).toHaveBeenCalledWith('/api/v1/admin/ops/metrics/query', expect.objectContaining({ name: 'http_requests_total' }));

    fixture.componentInstance.choose('jobs');
    fixture.detectChanges();
    expect(el.querySelector('[data-chart="apalis_pending_jobs"]')).toBeTruthy();
    // Not sampled, so not drawn.
    fixture.componentInstance.choose('cache');
    fixture.detectChanges();
    expect(el.querySelector('[data-chart="cache_hits_total"]')).toBeNull();
  });
});
