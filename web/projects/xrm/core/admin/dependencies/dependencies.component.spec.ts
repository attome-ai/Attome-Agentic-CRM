import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { DependenciesService } from '../data/services/dependencies.service';
import { DependenciesComponent } from './dependencies.component';

describe('DependenciesComponent (AB6-T9)', () => {
  function setUp() {
    const svc = {
      report: vi.fn(() => of({
        capabilities: {
          gated_routes: [
            { capability: 'object_storage', state: 'available', consecutive_failures: 0, enforced: true },
            { capability: 'email', state: 'unavailable', consecutive_failures: 4, enforced: true },
          ],
        },
        outbound: [
          { service: 'object_storage', state: 'closed', error_rate: 0.02, retries_1h: 3, endpoints: 1 },
          { service: 'smtp', state: 'open', error_rate: 0.8, retries_1h: 12, endpoints: 1 },
          { service: 'webhook', state: 'half_open', error_rate: null, retries_1h: 0, endpoints: 4 },
        ],
      })),
    };
    TestBed.configureTestingModule({
      imports: [DependenciesComponent],
      providers: [
        provideRouter([]),
        { provide: DependenciesService, useValue: svc },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: signal('en-US'), errorText: () => 'error' },
        },
      ],
    });
    const fixture = TestBed.createComponent(DependenciesComponent);
    fixture.detectChanges();
    return { root: fixture.nativeElement as HTMLElement };
  }

  it('shows open breaker in red', () => {
    const { root } = setUp();
    const breaker = (name: string) =>
      root.querySelector(`[data-outbound-row="${name}"] [data-breaker]`) as HTMLElement;
    expect(breaker('smtp').classList).toContain('dep-bad');
    expect(breaker('smtp').textContent?.trim()).toBe('dependenciesAdmin.breakerState.open');
    expect(breaker('object_storage').classList).toContain('dep-ok');
    expect(breaker('webhook').classList).toContain('dep-warn');
    const unavailable = root.querySelector('[data-capability-row="email"] [data-capability-state]');
    expect(unavailable?.classList).toContain('dep-bad');
  });

  it('formats the error rate and links webhooks to the dead letters', () => {
    const { root } = setUp();
    const rate = (name: string) =>
      root.querySelector(`[data-outbound-row="${name}"] [data-error-rate]`)?.textContent?.trim();
    expect(rate('smtp')).toBe('80%');
    expect(rate('webhook')).toBe('—');
    const link = root.querySelector('[data-dead-letters]') as HTMLAnchorElement;
    expect(link.getAttribute('href')).toBe('/xrm/admin/jobs/failed');
    expect(root.querySelector('[data-outbound-row="smtp"] [data-dead-letters]')).toBeNull();
  });
});
