import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';
import { describe, expect, it } from 'vitest';
import { ApiService } from './api.service';
import { ATTOME_CONFIG } from './config';
import { SdkService } from './sdk.service';
import type { ApiError } from './types';

function setup(): { sdk: SdkService; http: HttpTestingController; api: ApiService } {
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://api.test' } },
    ],
  });
  return {
    sdk: TestBed.inject(SdkService),
    http: TestBed.inject(HttpTestingController),
    api: TestBed.inject(ApiService),
  };
}

/** Lets the SDK's promise chain reach HttpClient. */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

describe('SdkService', () => {
  it('sends through HttpClient with the query, body and If-Match', async () => {
    const { sdk, http } = setup();
    const answer = firstValueFrom(
      sdk.patch<{ ok: boolean }>('/api/v1/thing/1', { body: { a: 1 }, ifMatch: 7, query: { x: 'y' } }),
    );
    await tick();
    const req = http.expectOne(r => r.url === 'http://api.test/api/v1/thing/1');
    expect(req.request.params.get('x')).toBe('y');
    expect(req.request.method).toBe('PATCH');
    expect(req.request.headers.get('If-Match')).toBe('"7"');
    expect(req.request.body).toEqual({ a: 1 });
    expect(req.request.withCredentials).toBe(true);
    req.flush({ ok: true });
    expect(await answer).toEqual({ ok: true });
    http.verify();
  });

  it('raises the same ApiError ApiService does', async () => {
    const { sdk, http } = setup();
    const answer = firstValueFrom(sdk.get('/api/v1/thing/2')).catch((e: ApiError) => e);
    await tick();
    http.expectOne('http://api.test/api/v1/thing/2').flush(
      { error: 'not_found', message: 'gone', request_id: 'r-1' },
      { status: 404, statusText: 'Not Found' },
    );
    const err = (await answer) as ApiError;
    expect(err.status).toBe(404);
    expect(err.kind).toBe('not_found');
    expect(err.requestId).toBe('r-1');
  });

  it('names the picked changeset on a write, not on a read', async () => {
    const { sdk, http, api } = setup();
    api.setChangeset('cs-1');
    const write = firstValueFrom(sdk.post('/api/v1/thing', { body: {} }));
    await tick();
    const post = http.expectOne('http://api.test/api/v1/thing');
    expect(post.request.headers.get('X-Attome-Changeset')).toBe('cs-1');
    post.flush({});
    await write;
    const read = firstValueFrom(sdk.get('/api/v1/thing'));
    await tick();
    const get = http.expectOne('http://api.test/api/v1/thing');
    expect(get.request.headers.has('X-Attome-Changeset')).toBe(false);
    get.flush({});
    await read;
  });

  it('marks a background read and answers a 304 with the caller\'s copy', async () => {
    const { sdk, http } = setup();
    const poll = firstValueFrom(sdk.getBackground('/api/v1/thing', { since: '1' }));
    await tick();
    const bg = http.expectOne(r => r.url === 'http://api.test/api/v1/thing');
    expect(bg.request.headers.get('x-attome-background')).toBe('1');
    expect(bg.request.params.get('since')).toBe('1');
    bg.flush([]);
    await poll;

    const fresh = firstValueFrom(sdk.getIfChanged<{ v: number }>('/api/v1/plan', null));
    await tick();
    const first = http.expectOne('http://api.test/api/v1/plan');
    expect(first.request.headers.has('If-None-Match')).toBe(false);
    first.flush({ v: 1 }, { headers: { ETag: 'W/"1"' } });
    expect(await fresh).toEqual({ body: { v: 1 }, etag: 'W/"1"' });

    const same = firstValueFrom(sdk.getIfChanged<{ v: number }>('/api/v1/plan', 'W/"1"'));
    await tick();
    const second = http.expectOne('http://api.test/api/v1/plan');
    expect(second.request.headers.get('If-None-Match')).toBe('W/"1"');
    second.flush(null, { status: 304, statusText: 'Not Modified' });
    expect(await same).toEqual({ body: null, etag: 'W/"1"' });
    http.verify();
  });
});
