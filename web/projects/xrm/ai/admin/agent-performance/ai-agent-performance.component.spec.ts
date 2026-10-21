import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiAgentPerformanceComponent, costAmount, defaultRange, trend } from './ai-agent-performance.component';
import type { AgentPerformance, AgentPerformanceDay } from './ai-agent-performance.service';

const PRICED: AgentPerformance = {
  agent_id: 'a1', name: 'followup_agent', tasks_done: 10, tasks_resolved: 7, tasks_measured: 8,
  effectiveness_sum: 6, handoffs: 1, input_tokens: 1000, output_tokens: 500, cost_micros: 60_000,
  cost_unit: 'price_list', time_saved_seconds: 1200, resolution_rate: 0.7, accuracy: 0.75,
  handoff_rate: 0.1, cost_per_task_micros: 6_000,
};
const UNPRICED: AgentPerformance = {
  ...PRICED, agent_id: 'a2', name: 'local_agent', cost_unit: null, cost_per_task_micros: null,
};
const DAYS: AgentPerformanceDay[] = [
  { day: '2027-03-01', tasks_done: 4, tasks_resolved: 3, tasks_measured: 3, effectiveness_sum: 2.5,
    handoffs: 0, input_tokens: 400, output_tokens: 200, cost_micros: 24_000, cost_unit: 'price_list',
    time_saved_seconds: 480 },
];

const BEHAVIOUR = {
  agent_id: 'a1', name: 'followup_agent', status: 'suspended', row_version: 7,
  baseline: {
    computed_at: '2027-03-01T03:00:00Z', first_activity_at: '2027-02-01T09:00:00Z',
    mean_writes_per_hour: 5, stddev_writes_per_hour: 2, mean_deletes_per_hour: 0,
    stddev_deletes_per_hour: 0, usual_entities: ['deal'], usual_hours: [9, 10],
  },
  hours: [{ hour: '2027-03-01T09:00:00Z', writes: 200, deletes: 0, external_calls: 0, entities: ['deal'] }],
  last_trip: { at: '2027-03-01T09:20:00Z', reason: 'automatic: volume: observed 200, expected 5' },
};

describe('AiAgentPerformanceComponent (AI8-T6)', () => {
  function create() {
    const get = vi.fn((path: string) => {
      if (path.includes('/behaviour')) return of(BEHAVIOUR);
      if (path.includes('/runs')) return of({ items: [], next_cursor: null });
      if (path.includes('/daily')) return of({ items: DAYS, total: 1, page: 1, page_size: 400 });
      return of({ items: [PRICED, UNPRICED], total: 2, page: 1, page_size: 500 });
    });
    TestBed.configureTestingModule({
      imports: [AiAgentPerformanceComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-US' },
        },
      ],
    });
    const fixture = TestBed.createComponent(AiAgentPerformanceComponent);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('shows no price set rather than a zero cost', () => {
    const { fixture } = create();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelectorAll('tr[data-agent]').length).toBe(2);
    expect(el.querySelector('tr[data-agent="a2"] [data-no-price]')?.textContent).toContain('aiPerformance.noPrice');
    expect(el.querySelector('tr[data-agent="a1"] [data-no-price]')).toBeNull();
    expect(costAmount(6_000, 'price_list')).toBe(0.006);
    expect(costAmount(6_000, null)).toBeNull();
  });

  it('opens the runs behind a day number', () => {
    const { fixture, get } = create();
    const c = fixture.componentInstance;
    c.select(PRICED);
    expect(get).toHaveBeenCalledWith(
      `/api/v1/admin/ai/agents/a1/performance/daily?from=${c.from}&to=${c.to}`,
    );
    c.openRuns('2027-03-01', 'handoffs');
    expect(get).toHaveBeenCalledWith('/api/v1/admin/ai/agents/a1/runs?day=2027-03-01&metric=handoffs');
    expect(c.runsFor()).toEqual({ day: '2027-03-01', metric: 'handoffs' });
  });

  it('shows the trip reason', () => {
    const { fixture } = create();
    fixture.componentInstance.select(PRICED);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="trip"]')?.textContent).toContain('aiPerformance.behaviour.stopped');
    expect(el.querySelector('[data-testid="trip-reason"]')?.textContent).toContain('automatic: volume');
    expect(el.querySelector('[data-testid="switch-on"]')).not.toBeNull();
  });

  it('builds the trend and the default range', () => {
    const t = trend(DAYS, { done: 'done', resolved: 'resolved' });
    expect(t.categories).toEqual([{ trackKey: '2027-03-01', label: '2027-03-01' }]);
    expect(t.series.map(s => s.points[0]?.value)).toEqual([4, 3]);
    expect(defaultRange(new Date('2027-03-31T12:00:00Z'))).toEqual({ from: '2027-03-01', to: '2027-03-30' });
  });
});
