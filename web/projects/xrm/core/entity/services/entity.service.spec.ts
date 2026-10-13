import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import { EntityMetadataChangeService } from '@attome/xrm/core/admin/data';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from './entity.service';

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
  const fetchAndFlush = (name: string) => {
    const seen: unknown[] = [];
    service.getSchema(name).subscribe(s => seen.push(s));
    httpMock.expectOne(url(name)).flush(schema(name));
    return seen;
  };

  it('issues one request per entity and replays it to later subscribers', () => {
    const first = fetchAndFlush('account');

    const second: unknown[] = [];
    service.getSchema('account').subscribe(s => second.push(s));

    // No expectOne here on purpose: afterEach's verify() fails if a second
    // request was issued.
    expect(second).toEqual(first);
    expect(second[0]).toEqual(schema('account'));
  });

  it('caches each entity separately', () => {
    fetchAndFlush('account');
    fetchAndFlush('contact');

    const cached: unknown[] = [];
    service.getSchema('account').subscribe(s => cached.push(s));
    expect(cached[0]).toEqual(schema('account'));
  });

  it('refetches after an admin changes entity metadata', () => {
    fetchAndFlush('account');

    metadataChanged.notify();

    // The entry is gone, so this must hit the backend again.
    fetchAndFlush('account');
  });

  it('refetches an entity explicitly invalidated, and keeps the others', () => {
    fetchAndFlush('account');
    fetchAndFlush('contact');

    service.invalidateSchema('account');

    fetchAndFlush('account');

    const stillCached: unknown[] = [];
    service.getSchema('contact').subscribe(s => stillCached.push(s));
    expect(stillCached[0]).toEqual(schema('contact'));
  });

  it('refetches once the TTL has elapsed', () => {
    vi.useFakeTimers();
    fetchAndFlush('account');

    vi.advanceTimersByTime(5 * 60 * 1000 + 1);

    fetchAndFlush('account');
  });

  it('does not cache a failed request', () => {
    let failed = false;
    service.getSchema('account').subscribe({ error: () => (failed = true) });
    httpMock.expectOne(url('account')).flush('nope', { status: 500, statusText: 'Server Error' });
    expect(failed).toBe(true);

    // A cached error would be replayed here instead of a fresh request.
    fetchAndFlush('account');
  });
});
