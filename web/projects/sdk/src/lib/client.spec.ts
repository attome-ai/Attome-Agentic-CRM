import { describe, expect, it, vi } from 'vitest';
import { AttomeClient } from './client';
import type { AuthProvider } from './auth/types';

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

const noopAuth: AuthProvider = { applyAuth() {} };

describe('AttomeClient', () => {
  it('exposes get/post/patch/put/delete over the same transport', async () => {
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) =>
      jsonResponse(200, { method: init?.method ?? 'GET', url: String(url) }),
    );
    const client = new AttomeClient({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });

    expect((await client.get('/a')).data).toMatchObject({ method: 'GET' });
    expect((await client.post('/a')).data).toMatchObject({ method: 'POST' });
    expect((await client.patch('/a')).data).toMatchObject({ method: 'PATCH' });
    expect((await client.put('/a')).data).toMatchObject({ method: 'PUT' });
    expect((await client.delete('/a')).data).toMatchObject({ method: 'DELETE' });
  });

  it('paginate() drives PaginatedResponse<T> pages via the page query param', async () => {
    const fetchMock = vi.fn(async (url: string | URL | Request) => {
      const u = new URL(String(url));
      const page = Number(u.searchParams.get('page') ?? '1');
      if (page === 1) return jsonResponse(200, { items: ['a', 'b'], total: 3, page: 1, page_size: 2 });
      return jsonResponse(200, { items: ['c'], total: 3, page: 2, page_size: 2 });
    });
    const client = new AttomeClient({ baseUrl: 'http://x', auth: noopAuth, fetch: fetchMock as unknown as typeof fetch });

    const items: string[] = [];
    for await (const item of client.paginate<string>('/api/v1/contact')) items.push(item);
    expect(items).toEqual(['a', 'b', 'c']);
  });
});
