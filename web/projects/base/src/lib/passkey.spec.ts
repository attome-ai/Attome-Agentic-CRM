import { describe, expect, it } from 'vitest';
import {
  creationOptions, fromBase64Url, isPasskeyCancelled, requestOptions, toBase64Url,
} from './passkey';

describe('passkey JSON conversion (Q6-T2)', () => {
  it('round-trips base64url without padding', () => {
    const bytes = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255]);
    const encoded = toBase64Url(bytes);
    expect(encoded).not.toMatch(/[+/=]/);
    expect(new Uint8Array(fromBase64Url(encoded))).toEqual(bytes);
  });

  it('turns the creation options binary fields into bytes', () => {
    const options = creationOptions({
      rp: { id: 'crm.example.com', name: 'crm.example.com' },
      user: { id: toBase64Url(new Uint8Array([1, 2, 3])), name: 'sara@example.com', displayName: '' },
      challenge: toBase64Url(new Uint8Array([9, 9])),
      pubKeyCredParams: [{ type: 'public-key', alg: -8 }],
      excludeCredentials: [{ type: 'public-key', id: toBase64Url(new Uint8Array([7])), transports: ['internal'] }],
    });
    expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(new Uint8Array([9, 9]));
    expect(new Uint8Array(options.user.id as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(options.rp.id).toBe('crm.example.com');
    const excluded = options.excludeCredentials?.[0];
    expect(new Uint8Array(excluded?.id as ArrayBuffer)).toEqual(new Uint8Array([7]));
    expect(excluded?.transports).toEqual(['internal']);
  });

  it('turns the request options challenge into bytes', () => {
    const options = requestOptions({ challenge: toBase64Url(new Uint8Array([4])), rpId: 'crm.example.com' });
    expect(new Uint8Array(options.challenge as ArrayBuffer)).toEqual(new Uint8Array([4]));
    expect(options.allowCredentials).toBeUndefined();
  });

  it('refuses options without a user', () => {
    expect(() => creationOptions({ challenge: 'AA' })).toThrow();
  });

  it('knows a cancelled prompt', () => {
    expect(isPasskeyCancelled(Object.assign(new Error('x'), { name: 'NotAllowedError' }))).toBe(true);
    expect(isPasskeyCancelled(new Error('x'))).toBe(false);
    expect(isPasskeyCancelled({ status: 401 })).toBe(false);
  });
});
