import { describe, expect, it } from 'vitest';
import { recordContextFromUrl } from './record-context';

const ID = '01900000-0000-7000-8000-0000000000a1';

describe('recordContextFromUrl', () => {
  it('reads the entity and record from an entity form URL', () => {
    expect(recordContextFromUrl(`/xrm/entity/contact/form?id=${ID}`)).toEqual({
      entity: 'contact',
      record_id: ID,
    });
    expect(recordContextFromUrl(`/xrm/entity/entity_info/form?id=${ID}&tab=2`)).toEqual({
      entity: 'entity_info',
      record_id: ID,
    });
    // A short pack route reads its segments as one underscored name.
    expect(recordContextFromUrl(`/xrm/cost/center/form?id=${ID}`)).toEqual({
      entity: 'cost_center',
      record_id: ID,
    });
  });

  it('is null anywhere that is not a saved record form', () => {
    for (const url of [
      '/xrm/entity/contact/list',
      '/xrm/entity/contact/form',
      `/xrm/entity/contact/form?id=not-a-uuid`,
      `/admin/form?id=${ID}`,
      `/xrm/entity/Contact/form?id=${ID}`,
      '/',
    ]) {
      expect(recordContextFromUrl(url), url).toBeNull();
    }
  });
});
