import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AdminAiService } from '../../services/admin-ai.service';
import { AiBotAnalyticsComponent } from './ai-bot-analytics.component';

const REPORT = {
  from: '2026-09-16T00:00:00Z',
  to: '2026-09-23T00:00:00Z',
  surface: null,
  turns: { started: 10, ended: 9, completed: 6, awaiting: 1, cancelled: 1, failed: 1, completion_rate: 0.6667, by_terminal_state: {} },
  tool_calls: { total: { proposed: 4, completed: 3, rejected: 0, invalidated: 0, expired: 0, approval_required: 1 }, by_action: [] },
  handoffs: { total: 3, by_reason: { refusal: 2, user_requested: 1, low_confidence: 0 } },
  deflection: { engaged: 5, deflected: 3, handed_off: 1, unresolved: 1, deflection_rate: 0.6, handoff_rate: 0.2 },
  feedback: { answers: 6, rated_answers: 2, up: 1, down: 1, up_rate: 0.5, coverage: null },
};

describe('AiBotAnalyticsComponent', () => {
  let adminAi: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    adminAi = { botAnalytics: vi.fn().mockReturnValue(of(REPORT)) };
    TestBed.configureTestingModule({
      imports: [AiBotAnalyticsComponent],
      providers: [
        { provide: AdminAiService, useValue: adminAi },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en-US' } },
      ],
    });
    TestBed.overrideComponent(AiBotAnalyticsComponent, { set: { template: '' } });
  });

  function create() {
    const fixture = TestBed.createComponent(AiBotAnalyticsComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  it('shows the server figures, and a dash where there is no denominator', () => {
    const c = create();
    expect(c.visible()).toBe(true);
    expect(c.percent(c.report()!.turns.completion_rate)).toBe('67%');
    expect(c.percent(c.report()!.feedback.coverage)).toBe('—');
    expect(c.handoffReasons().map(([reason]) => reason)).toEqual(['refusal', 'user_requested']);
  });

  it('asks for a seven-day window, then thirty on request', () => {
    const c = create();
    const [from, to] = adminAi['botAnalytics'].mock.calls[0] as [string, string];
    expect(Date.parse(to) - Date.parse(from)).toBe(7 * 24 * 60 * 60 * 1000);
    c.select(30);
    const [from30, to30] = adminAi['botAnalytics'].mock.calls[1] as [string, string];
    // Switching window again drops the report still in flight: the last click wins.
    c.select(7);
    expect(adminAi['botAnalytics']).toHaveBeenCalledTimes(3);
    expect(Date.parse(to30) - Date.parse(from30)).toBe(30 * 24 * 60 * 60 * 1000);
  });

  it('stays hidden for a caller who is not an administrator', () => {
    adminAi['botAnalytics'].mockReturnValue(throwError(() => ({ status: 403, message: 'no' })));
    const c = create();
    expect(c.visible()).toBe(false);
    expect(c.error()).toBeNull();
  });
});
