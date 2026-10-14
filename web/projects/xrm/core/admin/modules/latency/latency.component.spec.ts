import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { LatencyComponent } from './latency.component';

describe('LatencyComponent (AA1-T7)', () => {
  function create(report: unknown) {
    const get = vi.fn().mockReturnValue(of(report));
    TestBed.configureTestingModule({
      imports: [LatencyComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(LatencyComponent);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('lists routes, marks slow ones and filters', () => {
    const { fixture, get } = create({
      enabled: true,
      routes: [
        { method: 'POST', endpoint: '/api/v1/query/execute', count: 40, p50_ms: 120, p95_ms: 800, p99_ms: 1200 },
        { method: 'GET', endpoint: '/api/v1/{entity}/{id}', count: 300, p50_ms: 8, p95_ms: 25, p99_ms: 40 },
      ],
    });
    expect(get).toHaveBeenCalledWith('/api/v1/admin/latency');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('tbody tr').length).toBe(2);
    expect(el.querySelector('[data-route="POST /api/v1/query/execute"]')?.classList).toContain('lt-slow');
    fixture.componentInstance.filter.set('query');
    fixture.detectChanges();
    expect(el.querySelectorAll('tbody tr').length).toBe(1);
  });

  it('says so when metrics are off', () => {
    const { fixture } = create({ enabled: false, routes: [] });
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('latencyPage.disabled');
  });
});
