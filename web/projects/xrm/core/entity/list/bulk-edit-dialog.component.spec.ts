import { describe, expect, it } from 'vitest';
import type { FieldSchema } from '@attome/xrm';
import {
  buildBulkUpdateEnvelopes, bulkEditableFields, firstBulkError, isBulkTerminal,
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
});
