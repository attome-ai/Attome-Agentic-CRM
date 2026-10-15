import { describe, expect, it } from 'vitest';

import { liveRows } from './live-rows';

describe('liveRows (A13-T4)', () => {
  const shown = new Set(['r1', 'r2']);

  it('counts new records and reloads for a shown one that changed', () => {
    expect(liveRows('account', { changes: [
      { entity: 'account', id: 'r9', op: 'create' },
      { entity: 'account', id: 'r1', op: 'update' },
      { entity: 'contact', id: 'r2', op: 'delete' },
    ] }, shown)).toEqual({ created: 1, reload: true, overflow: false });
  });

  it('ignores changes to records it does not show', () => {
    expect(liveRows('account', { changes: [{ entity: 'account', id: 'r7', op: 'update' }] }, shown))
      .toEqual({ created: 0, reload: false, overflow: false });
  });

  it('passes an overflow on', () => {
    expect(liveRows('account', { overflow: true }, shown)).toEqual({ created: 0, reload: false, overflow: true });
  });
});
