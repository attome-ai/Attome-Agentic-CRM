import { describe, expect, it } from 'vitest';
import { ApiKeyAuth } from './api-key';

describe('ApiKeyAuth', () => {
  it('sets Authorization: ApiKey <public>:<secret>, matching attome-server auth.rs byte-for-byte', async () => {
    const auth = new ApiKeyAuth('atk_pub_abc123', 'atk_sec_def456');
    const headers = new Headers();
    await auth.applyAuth({ method: 'GET', pathAndQuery: '/api/v1/contact', headers, body: null });
    expect(headers.get('authorization')).toBe('ApiKey atk_pub_abc123:atk_sec_def456');
  });

  it('sets no credentialsMode (no cookie needed for this scheme)', () => {
    expect(new ApiKeyAuth('p', 's').credentialsMode).toBeUndefined();
  });

  it('rejects an empty public key or secret rather than silently sending a broken header', () => {
    expect(() => new ApiKeyAuth('', 'secret')).toThrow();
    expect(() => new ApiKeyAuth('pub', '')).toThrow();
  });
});
