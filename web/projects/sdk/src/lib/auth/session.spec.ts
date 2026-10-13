import { describe, expect, it } from 'vitest';
import { SessionAuth } from './session';

describe('SessionAuth', () => {
  it('requests credentials: include so the browser attaches the session cookie', () => {
    expect(new SessionAuth().credentialsMode).toBe('include');
  });

  it('sets no headers itself — the cookie is the credential, not anything this class computes', async () => {
    const auth = new SessionAuth();
    const headers = new Headers();
    await auth.applyAuth({ method: 'GET', pathAndQuery: '/api/v1/whoami', headers, body: null });
    expect([...headers.keys()]).toEqual([]);
  });
});
