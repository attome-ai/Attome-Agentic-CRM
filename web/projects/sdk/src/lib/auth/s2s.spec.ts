import { createHmac, createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { S2sAuth } from './s2s';

/** Independent re-implementation of the server's canonical message + HMAC,
 * using Node's built-in crypto rather than this SDK's own code, so this test
 * cannot pass merely because both sides share a bug. Mirrors
 * crates/engine/attome-s2s/src/crypto.rs::canonical_message + verify_hmac exactly. */
function expectedSignature(
  secretHex: string,
  method: string,
  pathAndQuery: string,
  bodyBytes: Buffer,
  timestampMs: string,
  nonce: string,
): string {
  const bodyHashHex = createHash('sha256').update(bodyBytes).digest('hex');
  const canonical = `${method}\n${pathAndQuery}\n${bodyHashHex}\n${timestampMs}\n${nonce}`;
  return createHmac('sha256', Buffer.from(secretHex, 'hex')).update(canonical).digest('hex');
}

describe('S2sAuth', () => {
  const secretHex = 'a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff';

  it('signs exactly like crates/engine/attome-s2s/src/crypto.rs (canonical message + HMAC-SHA256)', async () => {
    const auth = new S2sAuth({
      clientId: 'client-42',
      keyId: 'key-1',
      secretHex,
      now: () => 1_720_000_000_000,
      nonce: () => 'fixed-nonce',
    });

    const bodyBytes = new TextEncoder().encode('{"name":"widget"}');
    const headers = new Headers();
    await auth.applyAuth({
      method: 'POST',
      pathAndQuery: '/api/v1/widgets?x=1',
      headers,
      body: bodyBytes,
    });

    expect(headers.get('x-s2s-client-id')).toBe('client-42');
    expect(headers.get('x-s2s-key-id')).toBe('key-1');
    expect(headers.get('x-s2s-timestamp')).toBe('1720000000000');
    expect(headers.get('x-s2s-nonce')).toBe('fixed-nonce');

    const expected = expectedSignature(
      secretHex,
      'POST',
      '/api/v1/widgets?x=1',
      Buffer.from(bodyBytes),
      '1720000000000',
      'fixed-nonce',
    );
    expect(headers.get('x-s2s-signature')).toBe(expected);
  });

  it('signs the empty body as the sha256 of zero bytes for a bodyless GET', async () => {
    const auth = new S2sAuth({
      clientId: 'c',
      keyId: 'k',
      secretHex,
      now: () => 1_000,
      nonce: () => 'n',
    });
    const headers = new Headers();
    await auth.applyAuth({ method: 'GET', pathAndQuery: '/api/v1/widgets', headers, body: null });

    const expected = expectedSignature(secretHex, 'GET', '/api/v1/widgets', Buffer.alloc(0), '1000', 'n');
    expect(headers.get('x-s2s-signature')).toBe(expected);
  });

  it('produces a different signature if any single canonical field changes (matches the server test matrix)', async () => {
    const base = { clientId: 'c', keyId: 'k', secretHex, now: () => 1000, nonce: () => 'n' };
    async function sign(overrides: { method?: string; pathAndQuery?: string; body?: Uint8Array | null }) {
      const auth = new S2sAuth(base);
      const headers = new Headers();
      await auth.applyAuth({
        method: overrides.method ?? 'GET',
        pathAndQuery: overrides.pathAndQuery ?? '/api/v1/x',
        headers,
        body: overrides.body ?? null,
      });
      return headers.get('x-s2s-signature');
    }

    const baseline = await sign({});
    expect(await sign({ method: 'POST' })).not.toBe(baseline);
    expect(await sign({ pathAndQuery: '/api/v1/y' })).not.toBe(baseline);
    expect(await sign({ body: new TextEncoder().encode('x') })).not.toBe(baseline);
  });

  it('rejects a malformed (odd-length or non-hex) secret rather than signing with a truncated key', async () => {
    const auth = new S2sAuth({ clientId: 'c', keyId: 'k', secretHex: 'not-hex' });
    await expect(
      auth.applyAuth({ method: 'GET', pathAndQuery: '/api/v1/x', headers: new Headers(), body: null }),
    ).rejects.toThrow();
  });

  it('requires clientId, keyId and secretHex at construction', () => {
    expect(() => new S2sAuth({ clientId: '', keyId: 'k', secretHex })).toThrow();
    expect(() => new S2sAuth({ clientId: 'c', keyId: '', secretHex })).toThrow();
    expect(() => new S2sAuth({ clientId: 'c', keyId: 'k', secretHex: '' })).toThrow();
  });
});
