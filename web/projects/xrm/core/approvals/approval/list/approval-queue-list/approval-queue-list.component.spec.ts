import { describe, expect, it } from 'vitest';

import { agentChange } from './approval-queue-list.component';

describe('agentChange (N30-T10)', () => {
  it('reads an agent request into a diff and a quoted rationale', () => {
    const change = agentChange('attome-ai/invoke:record.update', {
      action_id: 'record.update',
      agent_rationale: 'The customer asked for it.',
      target: {
        entity: 'lead', record_id: 'r1', row_version: 3,
        before: { status: 'open', amount: null }, after: { status: 'won', amount: 5 },
      },
    });
    expect(change?.action).toBe('record.update');
    expect(change?.entity).toBe('lead');
    expect(change?.rows).toEqual([
      { field: 'amount', before: '—', after: '5' },
      { field: 'status', before: 'open', after: 'won' },
    ]);
    expect(change?.rationale).toBe('The customer asked for it.');
  });

  it('leaves other requests to the raw payload view', () => {
    expect(agentChange('metadata/schema-change', {})).toBeNull();
    const bare = agentChange('attome-ai/invoke', { action_id: 'agent.kill' });
    expect(bare?.rows).toEqual([]);
    expect(bare?.entity).toBeNull();
  });
});
