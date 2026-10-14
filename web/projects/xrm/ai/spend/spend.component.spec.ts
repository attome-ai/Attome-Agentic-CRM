import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiSpendComponent, SpendLine, forecastOver, spendState } from './spend.component';

const line = (percent: number, forecast = 0, cap = 100): SpendLine => ({
  scope: 'spend_feature', key: 'record.summarize', spent: percent, cap, percent, forecast,
});

describe('AiSpendComponent (N24-T2)', () => {
  it('classifies a line as within, near or over its cap', () => {
    expect(spendState(line(10), 80)).toBe('ok');
    expect(spendState(line(80), 80)).toBe('near');
    expect(spendState(line(100), 80)).toBe('over');
    expect(forecastOver(line(10, 120))).toBe(true);
    expect(forecastOver(line(10, 90))).toBe(false);
    expect(forecastOver(line(0, 5, 0))).toBe(false);
  });

  it('shows each window with its spend, forecast and state', () => {
    const api = {
      get: vi.fn().mockReturnValue(of({
        model: 'gpt-x', priced: true, degrade_at_percent: 80, window_days: 30,
        lines: [
          { scope: 'spend_deployment', key: '', spent: 30, cap: 100, percent: 30, forecast: 90 },
          { scope: 'spend_feature', key: 'record.summarize', spent: 9, cap: 10, percent: 90, forecast: 27 },
        ],
      })),
    };
    TestBed.configureTestingModule({
      imports: [AiSpendComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(AiSpendComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(api.get).toHaveBeenCalledWith('/api/v1/admin/ai/spend');
    const deployment = el.querySelector('[data-line="spend_deployment/"]');
    expect(deployment?.getAttribute('data-state')).toBe('ok');
    expect(deployment?.textContent).toContain('30 / 100');
    const feature = el.querySelector('[data-line="spend_feature/record.summarize"]');
    expect(feature?.getAttribute('data-state')).toBe('near');
    expect(feature?.textContent).toContain('aiSpend.forecastOver');
    expect(el.querySelector('[data-test="unpriced"]')).toBeNull();
  });
});
