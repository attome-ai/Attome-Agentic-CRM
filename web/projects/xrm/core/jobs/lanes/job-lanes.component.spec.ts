import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { JobLane, JobLanesComponent, ageLabel, rateLabel } from './job-lanes.component';

const LANES: JobLane[] = [
  {
    queue: 'fast', pending: 4, running: 2, retrying: 1, dead_letters: 3,
    oldest_pending_age_secs: 750, done_last_hour: 30, failed_last_hour: 10, failure_rate_last_hour: 0.25,
  },
  {
    queue: 'batch', pending: 0, running: 0, retrying: 0, dead_letters: 0,
    oldest_pending_age_secs: null, done_last_hour: 0, failed_last_hour: 0, failure_rate_last_hour: null,
  },
];

describe('JobLanesComponent (Z7-T6)', () => {
  function create() {
    const get = vi.fn((_url: string) => of({ items: LANES, total: 2, page: 1, page_size: 2 }));
    TestBed.configureTestingModule({
      imports: [JobLanesComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(JobLanesComponent);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('shows each queue with its depth, oldest wait and failure rate', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/admin/jobs/lanes');
    const fast: HTMLElement = fixture.nativeElement.querySelector('[data-lane="fast"]');
    expect(fast.textContent).toContain('12 min');
    expect(fast.textContent).toContain('25%');
    expect(fast.textContent).toContain('(10/40)');
    expect(fast.querySelectorAll('.jl-warn').length).toBe(2);
    const batch: HTMLElement = fixture.nativeElement.querySelector('[data-lane="batch"]');
    expect(batch.querySelectorAll('.jl-warn').length).toBe(0);
    expect(batch.textContent).toContain('—');
  });

  it('labels waits and rates', () => {
    expect(ageLabel(null)).toBe('—');
    expect(ageLabel(45.9)).toBe('45 s');
    expect(ageLabel(7200)).toBe('2 h');
    expect(rateLabel(undefined)).toBe('—');
    expect(rateLabel(0.333)).toBe('33%');
  });
});
