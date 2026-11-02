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
});
