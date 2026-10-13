import { describe, expect, it, vi } from 'vitest';
import { AttomeTransport, CHANGESET_HEADER } from './transport';
import type { AuthProvider } from './auth/types';
import { ApiError } from './errors';

function jsonResponse(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

const noopAuth: AuthProvider = { applyAuth() {} };

describe('AttomeTransport', () => {
  it('requires a baseUrl', () => {
    expect(() => new AttomeTransport({ baseUrl: '', auth: noopAuth })).toThrow();
  });

  it('builds the URL from baseUrl + path + query, and strips a trailing slash off baseUrl', async () => {
    const fetchMock = vi.fn(async (_url: string | URL | Request) => jsonResponse(200, { ok: true }));
    const transport = new AttomeTransport({ baseUrl: 'http://localhost:7865/', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });

    await transport.request('GET', '/api/v1/contact', { query: { page: 2, active: true, missing: undefined } });

    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toBe('http://localhost:7865/api/v1/contact?page=2&active=true');
  });

  it('JSON-serializes a plain object body and sets content-type', async () => {
    const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
      expect(init?.body).toBe(JSON.stringify({ name: 'widget' }));
      expect((init?.headers as Headers).get('content-type')).toBe('application/json');
      return jsonResponse(201, { id: '1' });
    });
    const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });
    await transport.request('POST', '/api/v1/widgets', { body: { name: 'widget' } });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('sends a Uint8Array body as-is with no forced content-type', async () => {
    const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
      expect((init?.headers as Headers).has('content-type')).toBe(false);
      return jsonResponse(200, {});
    });
    const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });
    await transport.request('POST', '/api/v1/upload', { body: new Uint8Array([1, 2, 3]) });
  });

  it('sets Idempotency-Key and If-Match/If-None-Match headers from RequestOptions', async () => {
    const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
      const h = init?.headers as Headers;
      expect(h.get('x-idempotency-key')).toBe('idem-123');
      expect(h.get('If-Match')).toBe('"5"');
      expect(h.get('If-None-Match')).toBe('"9"');
      return jsonResponse(200, {});
    });
    const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });
    await transport.request('PATCH', '/api/v1/contact/1', {
      idempotencyKey: 'idem-123',
      ifMatch: 5,
      ifNoneMatch: 9,
      body: { name: 'x' },
    });
  });

  it('delegates auth via applyAuth, passing method/pathAndQuery/body for S2S-style signers', async () => {
    const applyAuth = vi.fn(async (ctx: { method: string; pathAndQuery: string; headers: Headers; body: Uint8Array | null }) => {
      expect(ctx.method).toBe('POST');
      expect(ctx.pathAndQuery).toBe('/api/v1/x?a=1');
      expect(ctx.body).toEqual(new TextEncoder().encode(JSON.stringify({ y: 1 })));
      ctx.headers.set('x-signed', 'yes');
    });
    const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
      expect((init?.headers as Headers).get('x-signed')).toBe('yes');
      return jsonResponse(200, {});
    });
    const transport = new AttomeTransport({
      baseUrl: 'http://x',
      auth: { applyAuth },
      fetch: fetchMock as unknown as typeof fetch,
    });
    await transport.request('POST', '/api/v1/x', { query: { a: 1 }, body: { y: 1 } });
    expect(applyAuth).toHaveBeenCalledTimes(1);
  });

  it('passes credentials through from the auth provider (SessionAuth-style)', async () => {
    const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
      expect(init?.credentials).toBe('include');
      return jsonResponse(200, {});
    });
    const transport = new AttomeTransport({
      baseUrl: 'http://x',
      auth: { applyAuth() {}, credentialsMode: 'include' },
      fetch: fetchMock as unknown as typeof fetch,
    });
    await transport.request('GET', '/api/v1/whoami');
  });

  it('returns data/status/headers/requestId on success', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(200, { id: '1' }, { 'x-request-id': 'req-9' }));
    const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });
    const resp = await transport.request<{ id: string }>('GET', '/api/v1/contact/1');
    expect(resp.data).toEqual({ id: '1' });
    expect(resp.status).toBe(200);
    expect(resp.requestId).toBe('req-9');
  });

  it('throws a typed ApiError on a non-2xx response, matching the AppError JSON contract', async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(409, { error: 'version_conflict', message: 'stale row_version', request_id: 'req-7' }),
    );
    const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });

    await expect(transport.request('PATCH', '/api/v1/contact/1', { ifMatch: 3 })).rejects.toMatchObject({
      status: 409,
      kind: 'version_conflict',
      requestId: 'req-7',
    });
  });

  it('propagates a real ApiError instance, not just an object shape', async () => {
    const fetchMock = vi.fn(async () => jsonResponse(404, { error: 'not_found', message: 'no such record' }));
    const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });
    try {
      await transport.request('GET', '/api/v1/contact/missing');
      expect.unreachable('should have thrown');
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
    }
  });

  it('handles an empty response body (e.g. 204) without throwing on JSON.parse', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 204 }));
    const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });
    const resp = await transport.request('DELETE', '/api/v1/contact/1');
    expect(resp.data).toBeUndefined();
    expect(resp.status).toBe(204);
  });
  describe('changesetId (Solution 7, D-785)', () => {
    const ID = '0199aaaa-0000-7000-8000-000000000001';

    function capture() {
      const seen: { method: string; header: string | null }[] = [];
      const fetchMock = vi.fn(async (_url: unknown, init?: RequestInit) => {
        seen.push({ method: String(init?.method), header: (init?.headers as Headers).get(CHANGESET_HEADER) });
        return jsonResponse(200, {});
      });
      return { seen, fetchMock: fetchMock as unknown as typeof fetch };
    }

    it('sends X-Attome-Changeset on every mutating method, never on GET', async () => {
      const { seen, fetchMock } = capture();
      const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock, changesetId: ID });
      for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
        await transport.request(method, '/api/v1/admin/entities');
      }
      expect(seen).toEqual([
        { method: 'GET', header: null },
        { method: 'POST', header: ID },
        { method: 'PUT', header: ID },
        { method: 'PATCH', header: ID },
        { method: 'DELETE', header: ID },
      ]);
    });

    it('sends nothing when the option is unset', async () => {
      const { seen, fetchMock } = capture();
      const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock });
      await transport.request('POST', '/api/v1/admin/entities', { body: {} });
      expect(seen[0].header).toBeNull();
    });

    it('a per-call changesetId overrides the client option, and null suppresses it', async () => {
      const { seen, fetchMock } = capture();
      const transport = new AttomeTransport({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock, changesetId: ID });
      await transport.request('POST', '/api/v1/admin/entities', { changesetId: 'other-id' });
      await transport.request('POST', '/api/v1/admin/entities', { changesetId: null });
      expect(seen.map(s => s.header)).toEqual(['other-id', null]);
    });
  });
});
