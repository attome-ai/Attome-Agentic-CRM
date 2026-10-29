import { TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { of } from 'rxjs';
import { describe, expect, it } from 'vitest';
import { LangService } from '@attome/base';
import { DashboardService, ScorecardItem, ScorecardRead } from '@attome/xrm/dashboard/data';
import { MetricScorecardComponent, freshnessBadge, statusBand } from './metric-scorecard.component';
import { previewChildren, sharesBody } from '../target-spread-dialog/target-spread-dialog.component';

function item(over: Partial<ScorecardItem> = {}): ScorecardItem {
  return {
    metric_id: 'm1', name: 'Win rate', key: 'win_rate', period: 'month', unit: '%', sort_order: 0,
    period_start: '2026-09-01', actual: 42, status: 'on_track', target: 40,
    freshness: { computed_at: '2026-09-02T00:00:00Z', is_stale: false, failed: false },
    ...over,
  };
}

describe('metric scorecard (P9-T15)', () => {
  it('bands a row by its status and badges a stale or failed value', () => {
    expect(statusBand('on_track')).toBe('good');
    expect(statusBand('at_risk')).toBe('warn');
    expect(statusBand('failed')).toBe('bad');
    expect(statusBand(null)).toBe('none');
    expect(freshnessBadge(item())).toBeNull();
    expect(freshnessBadge(item({ freshness: { computed_at: null, is_stale: true, failed: false } }))).toBe('stale');
    expect(freshnessBadge(item({ freshness: { computed_at: null, is_stale: true, failed: true } }))).toBe('failed');
  });

  it('only sends shares that add up to 100%', () => {
    expect(sharesBody([{ member: 'east', percent: 60 }, { member: 'west', percent: 40 }])).toEqual({ east: 0.6, west: 0.4 });
    expect(sharesBody([{ member: 'east', percent: 60 }, { member: 'west', percent: 30 }])).toBeNull();
    expect(sharesBody([{ member: ' ', percent: 100 }])).toBeNull();
    expect(previewChildren(1000, [{ member: 'east', percent: 60 }])).toEqual([{ member: 'east', value: 600 }]);
  });

  it('shows stale badge and the period comment', () => {
    const card: ScorecardRead = {
      id: 'c1', name: 'Board', description: null,
      items: [
        item(),
        item({ metric_id: 'm2', name: 'Pipeline', status: 'off_track', freshness: { computed_at: null, is_stale: true, failed: false } }),
      ],
    };
    TestBed.configureTestingModule({
      imports: [MetricScorecardComponent],
      providers: [
        {
          provide: DashboardService,
          useValue: {
            getScorecard: () => of(card),
            listComments: (id: string) => of({ items: id === 'm1' ? [{ id: 'k', body: 'Ahead of plan.', period_start: null, created_at: '' }] : [], total: 1 }),
          },
        },
        { provide: LangService, useValue: { translate: (key: string) => key, current: signal('en'), isRtl: () => false } },
      ],
    });
    const fixture = TestBed.createComponent(MetricScorecardComponent);
    fixture.componentRef.setInput('id', 'c1');
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const rows = el.querySelectorAll('[data-testid="scorecard-row"]');
    expect(rows.length).toBe(2);
    expect(rows[1].getAttribute('data-band')).toBe('bad');
    expect(el.querySelector('[data-testid="badge-stale"]')).not.toBeNull();
    expect(el.textContent).toContain('Ahead of plan.');
  });
});
