import { describe, expect, it } from 'vitest';
import { generateIdempotencyKey, IDEMPOTENCY_KEY_HEADER } from './idempotency';

describe('idempotency', () => {
  it('uses the exact header name the server gate reads', () => {
    // crates/foundation/attome-server/src/middleware/idempotency.rs: const HEADER = "x-idempotency-key";
    expect(IDEMPOTENCY_KEY_HEADER).toBe('x-idempotency-key');
  });

  it('generates a fresh v4-shaped UUID on every call', () => {
    const a = generateIdempotencyKey();
    const b = generateIdempotencyKey();
    const uuidV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(a).toMatch(uuidV4);
    expect(b).toMatch(uuidV4);
    expect(a).not.toBe(b);
  });
});
