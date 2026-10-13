import { describe, expect, it } from 'vitest';
import { relativeTime, slaBadgeState } from './sla-status';

const NOW = Date.parse('2026-09-23T12:00:00Z');
const IN_2H = '2026-09-23T14:00:00Z';
const AGO_2H = '2026-09-23T10:00:00Z';

describe('slaBadgeState', () => {
  it('is null for a missing ticket or one with no SLA at all', () => {
    expect(slaBadgeState(null, NOW)).toBeNull();
    expect(slaBadgeState({ status: 'new' }, NOW)).toBeNull();
  });

  it('is `due` while running inside the SLA', () => {
    expect(slaBadgeState({ sla_policy_id: 'p', resolution_due_at: IN_2H }, NOW))
      .toEqual({ kind: 'due', dueAt: new Date(IN_2H), reason: null });
  });

  it('is `warning` once the warning sweep has marked it', () => {
    expect(slaBadgeState({ sla_policy_id: 'p', resolution_due_at: IN_2H, sla_warned: true }, NOW)?.kind)
      .toBe('warning');
  });

  it('is `breached` once the breach sweep has marked it', () => {
    expect(slaBadgeState({ sla_policy_id: 'p', resolution_due_at: AGO_2H, sla_breached: true }, NOW)?.kind)
      .toBe('breached');
  });

  it('is `overdue` when the deadline passed but no sweep has marked it', () => {
    expect(slaBadgeState({ sla_policy_id: 'p', resolution_due_at: AGO_2H, sla_warned: true }, NOW)?.kind)
      .toBe('overdue');
  });

  it('is `resolved` (or `resolved_breached`) for a resolved or closed ticket', () => {
    expect(slaBadgeState({ sla_policy_id: 'p', resolution_due_at: AGO_2H, resolved_at: AGO_2H }, NOW)?.kind)
      .toBe('resolved');
    expect(slaBadgeState({ sla_policy_id: 'p', status: 'closed', sla_breached: true }, NOW)?.kind)
      .toBe('resolved_breached');
  });

  it('is `not_calculated` with the D-517 reason for an unresolved SLA', () => {
    expect(slaBadgeState({
      sla_policy_id: 'p', sla_calculation_status: 'unresolved', sla_unresolved_reason: 'calendar_unresolved',
    }, NOW)).toEqual({ kind: 'not_calculated', dueAt: null, reason: 'calendar_unresolved' });
  });

  it('is `not_calculated` without a reason for a policy with no deadline', () => {
    expect(slaBadgeState({ sla_policy_id: 'p', resolution_due_at: null }, NOW))
      .toEqual({ kind: 'not_calculated', dueAt: null, reason: null });
  });
});

describe('relativeTime', () => {
  it('uses minutes, hours or days depending on distance', () => {
    expect(relativeTime(new Date(NOW + 30 * 60_000), NOW, 'en-US')).toBe('in 30 minutes');
    expect(relativeTime(new Date(IN_2H), NOW, 'en-US')).toBe('in 2 hours');
    expect(relativeTime(new Date(AGO_2H), NOW, 'en-US')).toBe('2 hours ago');
    expect(relativeTime(new Date(NOW + 3 * 86_400_000), NOW, 'en-US')).toBe('in 3 days');
  });
});
