import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import { EntityMetadataChangeService } from '@attome/xrm/core/admin/data';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from './entity.service';

/** The SDK sends, and answers, a promise turn later (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

/**
 * PERF-3 (PLATFORM-REVIEW-2026-08-24 section 4) — `getSchema` is called
 * unconditionally by `EngineFormBase.ngOnInit`, so it runs on every navigation
 * into any of the ~30 entity screens. These specs pin the cache's contract:
 * one request per entity, dropped on a metadata mutation, dropped on TTL
 * expiry, and never caching a failure.
 *
 * `httpMock.verify()` in `afterEach` is what makes the "served from cache"
 * assertions real — an unexpected second request fails the spec rather than
 * passing silently.
 */
describe('EntityService schema cache', () => {
  let service: EntityService;
  let httpMock: HttpTestingController;
  let metadataChanged: EntityMetadataChangeService;

  const API = 'http://localhost:7865';
  // M05/D-426: `getSchema` always threads the active locale as `?locale=`.
  const url = (name: string) => `${API}/api/v1/schema/${name}?locale=en-US`;

  const schema = (name: string) => ({ logicalname: name, attributes: [] });

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
        { provide: LangService, useValue: { intlLocale: () => 'en-US' } },
      ],
    });
    service = TestBed.inject(EntityService);
    httpMock = TestBed.inject(HttpTestingController);
    metadataChanged = TestBed.inject(EntityMetadataChangeService);
  });

  afterEach(() => {
    vi.useRealTimers();
    httpMock.verify();
  });

  /** Subscribes, flushes the one expected request, and returns what arrived. */
  const fetchAndFlush = async (name: string) => {
    const seen: unknown[] = [];
    service.getSchema(name).subscribe(s => seen.push(s));
    await tick();
    httpMock.expectOne(url(name)).flush(schema(name));
    await tick();
    return seen;
  };

  it('issues one request per entity and replays it to later subscribers', async () => {
    const first = await fetchAndFlush('account');

    const second: unknown[] = [];
    service.getSchema('account').subscribe(s => second.push(s));
    await tick();

    // No expectOne here on purpose: afterEach's verify() fails if a second
    // request was issued.
    expect(second).toEqual(first);
    expect(second[0]).toEqual(schema('account'));
  });

  it('caches each entity separately', async () => {
    await fetchAndFlush('account');
    await fetchAndFlush('contact');

    const cached: unknown[] = [];
    service.getSchema('account').subscribe(s => cached.push(s));
    await tick();
    expect(cached[0]).toEqual(schema('account'));
  });

  it('refetches after an admin changes entity metadata', async () => {
    await fetchAndFlush('account');

    metadataChanged.notify();

    // The entry is gone, so this must hit the backend again.
    await fetchAndFlush('account');
  });

  it('refetches an entity explicitly invalidated, and keeps the others', async () => {
    await fetchAndFlush('account');
    await fetchAndFlush('contact');

    service.invalidateSchema('account');

    await fetchAndFlush('account');

    const stillCached: unknown[] = [];
    service.getSchema('contact').subscribe(s => stillCached.push(s));
    await tick();
    expect(stillCached[0]).toEqual(schema('contact'));
  });

  it('refetches once the TTL has elapsed', async () => {
    // Only the clock is fake: the TTL reads Date.now(), and the SDK's promise
    // turns still need real timers.
    vi.useFakeTimers({ toFake: ['Date'] });
    await fetchAndFlush('account');

    vi.setSystemTime(Date.now() + 5 * 60 * 1000 + 1);

    await fetchAndFlush('account');
  });

  it('does not cache a failed request', async () => {
    let failed = false;
    service.getSchema('account').subscribe({ error: () => (failed = true) });
    await tick();
    httpMock.expectOne(url('account')).flush('nope', { status: 500, statusText: 'Server Error' });
    await tick();
    expect(failed).toBe(true);

    // A cached error would be replayed here instead of a fresh request.
    await fetchAndFlush('account');
  });
});

describe('EntityService recycle bin (A18)', () => {
  const API = 'http://localhost:7865';

  function setUp() {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
        { provide: LangService, useValue: { intlLocale: () => 'en-US' } },
      ],
    });
    return { service: TestBed.inject(EntityService), httpMock: TestBed.inject(HttpTestingController) };
  }

  it('sends the operation id and reason with a delete, and undoes the operation', async () => {
    const { service, httpMock } = setUp();
    service.delete('account', 'a1', { operationId: 'op-1', reason: ' duplicate ' }).subscribe();
    await tick();
    const del = httpMock.expectOne(r => r.url === `${API}/api/v1/account/a1` && r.params.get('reason') === 'duplicate');
    expect(del.request.method).toBe('DELETE');
    expect(del.request.headers.get('Attome-Operation-Id')).toBe('op-1');
    del.flush(null);
    await tick();

    service.restoreOperation('op-1').subscribe();
    await tick();
    const undo = httpMock.expectOne(`${API}/api/v1/bin/operations/op-1/restore`);
    expect(undo.request.method).toBe('POST');
    undo.flush({ restored: 1, failed: [] });
    await tick();
    httpMock.verify();
  });

  it('sends a plain delete without them', async () => {
    const { service, httpMock } = setUp();
    service.delete('account', 'a2').subscribe();
    await tick();
    const del = httpMock.expectOne(`${API}/api/v1/account/a2`);
    expect(del.request.headers.has('Attome-Operation-Id')).toBe(false);
    del.flush(null);
    await tick();
    httpMock.verify();
  });
});
