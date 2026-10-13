import { describe, expect, it } from 'vitest';
import { principalRef, reassignBody, shareBody, summarizeAssign } from './record-access';

describe('record access helpers (U7 Phase A)', () => {
  const user = { kind: 'user' as const, id: 'u1', label: 'ann@example.com' };
  const team = { kind: 'team' as const, id: 't1', label: 'Support' };

  it('names a principal the way the share routes resolve it — exactly one field', () => {
    expect(principalRef(user)).toEqual({ user_email: 'ann@example.com' });
    expect(principalRef(team)).toEqual({ team_name: 'Support' });
  });

  it('builds the reassign and share bodies', () => {
    expect(reassignBody('ticket', 'r1', team)).toEqual({
      entity: 'ticket', record_id: 'r1', team_name: 'Support',
    });
    expect(shareBody('ticket', 'r1', user, 'deny')).toEqual({
      entity: 'ticket', record_id: 'r1', capability: 'deny', user_email: 'ann@example.com',
    });
  });

  it('summarizes a bulk assign per record', () => {
    expect(summarizeAssign([
      { recordId: 'a', ok: true },
      { recordId: 'b', ok: false, error: 'Forbidden' },
      { recordId: 'c', ok: true },
    ])).toEqual({ succeeded: 2, failed: [{ recordId: 'b', ok: false, error: 'Forbidden' }] });
  });
});
