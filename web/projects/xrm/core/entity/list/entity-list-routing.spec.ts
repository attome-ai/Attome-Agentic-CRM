import { describe, expect, it } from 'vitest';
import { resolveRouteTemplate } from './entity-list.component';
import { logicalToUrlPath } from '../services/entity-url.utils';

describe('resolveRouteTemplate', () => {
  it('derives generic entity paths from linked logical names', () => {
    expect(logicalToUrlPath('contact')).toBe('xrm/entity/contact');
    expect(logicalToUrlPath('user_account')).toBe('xrm/entity/user_account');
  });

  it('expands multiple named column placeholders and URL-encodes values', () => {
    expect(resolveRouteTemplate(
      '/xrm/entity/{{entity}}/form?id={{record_id}}',
      { entity: 'sales/order', record_id: 'abc 123' },
    )).toBe('/xrm/entity/sales%2Forder/form?id=abc%20123');
  });

  it('returns null when a named placeholder has no row value', () => {
    expect(resolveRouteTemplate('/records/{{missing_id}}', { id: 'record-1' })).toBeNull();
  });

  it('keeps the legacy id placeholder working', () => {
    expect(resolveRouteTemplate('/records/{id}', { id: 'record-1' })).toBe('/records/record-1');
  });

  it('rejects external route templates', () => {
    expect(resolveRouteTemplate('https://example.com/{{id}}', { id: 'record-1' })).toBeNull();
  });
});
