import { describe, expect, it } from 'vitest';
import type { FieldSchema } from '@attome/xrm';
import {
  buildBulkUpdateEnvelopes, buildEditRequest, bulkEditableFields, bulkFailures, firstBulkError, isBulkTerminal,
  opsFor, savedActionsFor, withSavedAction,
} from './bulk-edit-dialog.component';

describe('entity-list bulk edit (PROD-12)', () => {
  const field = (name: string, field_type: FieldSchema['field_type'], sort_order: number): FieldSchema => ({
    id: `f-${name}`, entity_id: 'e-1', name, display_name: name, field_type,
    options: null, sort_order, is_required: false,
  });

  it('offers every field except file uploads and the soft-delete flag, in form order', () => {
    const offered = bulkEditableFields([
      field('notes', 'text', 3),
      field('attachment', 'file', 1),
      field('is_active', 'bool', 0),
      field('status', 'choice', 2),
      // U9: an image is a file field; a formula is computed.
      field('photo', 'image', 4),
      field('total', 'formula', 5),
    ]);
    expect(offered.map(f => f.name)).toEqual(['status', 'notes']);
  });

  it('pins every envelope to the row_version read for that record', () => {
    const envelopes = buildBulkUpdateEnvelopes(
      [{ id: 'a', row_version: 3 }, { id: 'b', row_version: 7 }],
      'status',
      'closed',
    );
    expect(envelopes).toEqual([
      { id: 'a', expected_row_version: 3, data: { status: 'closed' } },
      { id: 'b', expected_row_version: 7, data: { status: 'closed' } },
    ]);
  });

  it('sends an explicit null when the field is being cleared', () => {
    expect(buildBulkUpdateEnvelopes([{ id: 'a', row_version: 1 }], 'owner', null)[0].data)
      .toEqual({ owner: null });
  });

  it('reads the first item error out of the bulk status, tolerating other shapes', () => {
    expect(firstBulkError([{ index: 2, error: 'row_version mismatch' }, { index: 4, error: 'x' }]))
      .toBe('row_version mismatch');
    expect(firstBulkError([{ index: 0 }, { index: 1, error: '  ' }, { index: 2, error: 'late' }])).toBe('late');
    expect(firstBulkError(null)).toBeNull();
    expect(firstBulkError('boom')).toBeNull();
    expect(firstBulkError([])).toBeNull();
  });

  it('treats only completed/failed as terminal — running/queued keep polling', () => {
    expect(isBulkTerminal('completed')).toBe(true);
    expect(isBulkTerminal('failed')).toBe(true);
    expect(isBulkTerminal('running')).toBe(false);
    expect(isBulkTerminal('queued')).toBe(false);
  });

  // ── B5-T4 ──

  it('offers each field only the operations the server accepts for it', () => {
    expect(opsFor({ ...field('n', 'number', 0) })).toEqual(['set', 'clear', 'increment']);
    expect(opsFor({ ...field('t', 'text', 0), is_required: true })).toEqual(['set']);
    const tags = { ...field('tags', 'choice', 0), options: { choices: ['a', 'b'], multi: true } } as FieldSchema;
    expect(opsFor(tags)).toEqual(['set', 'clear', 'add', 'remove']);
  });

  it('builds the request from the selection or the filters, numbers for increment, no value to clear', () => {
    const drafts = [
      { attribute: 'amount', op: 'increment' as const, value: '5' },
      { attribute: 'notes', op: 'clear' as const, value: 'ignored' },
    ];
    expect(buildEditRequest('selection', ['a', 'b'], [], drafts, false)).toEqual({
      ids: ['a', 'b'],
      operations: [{ attribute: 'amount', op: 'increment', value: 5 }, { attribute: 'notes', op: 'clear' }],
    });
    const filters = [{ field: 'status', op: 'eq', value: 'open' }];
    const byFilter = buildEditRequest('filters', ['a'], filters, drafts, true);
    expect(byFilter.ids).toBeUndefined();
    expect(byFilter.filters).toEqual(filters);
    expect(byFilter.quiet).toBe(true);
  });

  it('names the record and the reason of every item that was not changed', () => {
    const status = {
      items: [
        { index: 0, ok: { attempts: 1, record_id: 'a' } },
        { index: 1, problem: { code: 'version_conflict', message: 'stale' } },
        { index: 2, problem: { code: 'item_failed', message: 'required' } },
      ],
    };
    expect(bulkFailures(status, ['a', 'b', 'c'])).toEqual([
      { index: 1, recordId: 'b', reason: 'conflict', message: 'stale' },
      { index: 2, recordId: 'c', reason: 'failed', message: 'required' },
    ]);
    expect(bulkFailures({ errors: [{ index: 0, error: 'x' }] }, [])).toEqual([
      { index: 0, recordId: null, reason: 'failed', message: 'x' },
    ]);
    expect(bulkFailures(null, [])).toEqual([]);
  });

  it('saves a named bulk edit per entity, replacing one of the same name', () => {
    const first = withSavedAction({}, 'deal', { name: 'Close', operations: [{ attribute: 's', op: 'set', value: 'x' }] });
    const other = withSavedAction(first, 'lead', { name: 'Close', operations: [] });
    const again = withSavedAction(other, 'deal', { name: 'Close', operations: [{ attribute: 's', op: 'clear' }] });
    expect(savedActionsFor(again, 'deal')).toEqual([{ name: 'Close', operations: [{ attribute: 's', op: 'clear' }] }]);
    expect(savedActionsFor(again, 'lead')).toHaveLength(1);
    expect(savedActionsFor({ deal: [{ bad: true }] }, 'deal')).toEqual([]);
    expect(savedActionsFor('nonsense', 'deal')).toEqual([]);
  });
});
