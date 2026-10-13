import { describe, expect, it } from 'vitest';
import { displayValue, summarizeProposal, wantsCurrentRecord } from './proposal-diff';

describe('summarizeProposal', () => {
  it('diffs an update against the current record', () => {
    const summary = summarizeProposal(
      'record.update',
      { entity: 'support_case', record_id: 'r1', values: { status: 'closed', priority: 'high' }, row_version: 3 },
      { status: 'open', priority: 'high' },
    );
    expect(summary.entity).toBe('support_case');
    expect(summary.recordId).toBe('r1');
    expect(summary.rows).toEqual([
      { field: 'priority', current: 'high', proposed: 'high', changed: false },
      { field: 'status', current: 'open', proposed: 'closed', changed: true },
    ]);
  });

  it('shows proposed values alone when the current record is unavailable', () => {
    const summary = summarizeProposal('record.update_field', { entity: 'e', record_id: 'r', field: 'status', value: 'x' }, null);
    expect(summary.rows).toEqual([{ field: 'status', current: undefined, proposed: 'x', changed: true }]);
  });

  it('never compares a create against a record', () => {
    const summary = summarizeProposal('record.create', { entity: 'e', values: { name: 'A' } }, { name: 'B' });
    expect(summary.rows[0].current).toBeUndefined();
  });

  it('shows any other action’s arguments, without the target identity', () => {
    const summary = summarizeProposal('workflow.start', { definition_logicalname: 'onboard', context: { a: 1 } }, null);
    expect(summary.rows.map((r) => r.field)).toEqual(['context', 'definition_logicalname']);
    expect(summary.rows[0].proposed).toBe('{"a":1}');
  });

  it('renders every value as plain text', () => {
    expect(displayValue('<b>x</b>')).toBe('<b>x</b>');
    expect(displayValue(null)).toBe('—');
    expect(displayValue(3)).toBe('3');
  });

  it('asks for the current record only for edits', () => {
    expect(wantsCurrentRecord('record.update')).toBe(true);
    expect(wantsCurrentRecord('record.create')).toBe(false);
    expect(wantsCurrentRecord('record.delete')).toBe(false);
  });
});
