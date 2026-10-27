import { describe, expect, it } from 'vitest';
import { actionAllowed } from './allowed-actions';

describe('actionAllowed', () => {
  it('offers an operation the schema allows, and hides one it does not (Q10-T11)', () => {
    expect(actionAllowed(['read', 'export'], 'export')).toBe(true);
    expect(actionAllowed(['read', 'export'], 'delete')).toBe(false);
    expect(actionAllowed([], 'create')).toBe(false);
  });

  it('offers everything until the schema says otherwise; the API still decides', () => {
    expect(actionAllowed(null, 'delete')).toBe(true);
    expect(actionAllowed(undefined, 'bulk')).toBe(true);
  });
});
