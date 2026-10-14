import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService, UserPreferencesService } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SLA_BADGE_TICK_MS, SlaBadgeComponent } from './sla-badge.component';

describe('SlaBadgeComponent', () => {
  const NOW = Date.parse('2026-09-23T12:00:00Z');

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    TestBed.configureTestingModule({
      imports: [SlaBadgeComponent],
      providers: [
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US',
            translate: (key: string, params?: Record<string, unknown>) =>
              params ? `${key} ${JSON.stringify(params)}` : key,
          },
        },
        { provide: UserPreferencesService, useValue: { timezone: signal<string | null>('UTC'), calendar: () => null, digits: () => null } },
      ],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render(ticket: Record<string, unknown> | null) {
    const fixture = TestBed.createComponent(SlaBadgeComponent);
    fixture.componentRef.setInput('ticket', ticket);
    fixture.detectChanges();
    return fixture;
  }

  function badge(el: HTMLElement): HTMLElement | null {
    return el.querySelector('[data-testid="sla-badge"]');
  }

  it('renders nothing for a ticket with no SLA', () => {
    expect(badge(render({ status: 'new' }).nativeElement)).toBeNull();
  });

  it('shows "due in" with a relative time and the absolute time as its tooltip', () => {
    const el = render({ sla_policy_id: 'p', resolution_due_at: '2026-09-23T14:00:00Z' }).nativeElement;
    const b = badge(el)!;
    expect(b.dataset['kind']).toBe('due');
    expect(b.textContent).toContain('serviceSla.badge.due');
    expect(b.textContent).toContain('in 2 hours');
    expect(b.getAttribute('title')).toBeTruthy();
    expect(b.querySelector('i')?.getAttribute('aria-hidden')).toBe('true');
  });

  it('shows breached, resolved and the translated not-calculated reason', () => {
    expect(badge(render({ sla_policy_id: 'p', resolution_due_at: '2026-09-23T10:00:00Z', sla_breached: true })
      .nativeElement)!.textContent).toContain('serviceSla.badge.breached');
    expect(badge(render({ sla_policy_id: 'p', resolved_at: '2026-09-23T10:00:00Z' })
      .nativeElement)!.textContent).toContain('serviceSla.badge.resolved');
    const text = badge(render({
      sla_policy_id: 'p', sla_calculation_status: 'unresolved', sla_unresolved_reason: 'business_hours_invalid',
    }).nativeElement)!.textContent;
    expect(text).toContain('serviceSla.badge.notCalculatedReason');
    expect(text).toContain('serviceSla.reason.business_hours_invalid');
  });

  it('moves from due to overdue as time passes', () => {
    const fixture = render({ sla_policy_id: 'p', resolution_due_at: '2026-09-23T12:01:30Z' });
    expect(badge(fixture.nativeElement)!.dataset['kind']).toBe('due');
    vi.advanceTimersByTime(SLA_BADGE_TICK_MS * 2);
    fixture.detectChanges();
    expect(badge(fixture.nativeElement)!.dataset['kind']).toBe('overdue');
  });
});
