import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { S2sAdminService, type ClientListItem } from './s2s-admin.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

/**
 * Exercises the real `ApiService` against `HttpTestingController` rather than
 * mocking it. The whole job of this service is URL/method/parameter
 * construction — a mocked `ApiService` would assert only that this file calls
 * itself the way this file is written, which is the one thing that cannot
 * regress silently. Driving real HTTP pins the thing that can: a wrong path, a
 * dropped query parameter, a lost `withCredentials`.
 */
describe('S2sAdminService', () => {
  let service: S2sAdminService;
  let httpMock: HttpTestingController;

  const API = 'http://localhost:7865';
  const S2S = `${API}/api/v1/admin/s2s/clients`;

  const client = (id: string): ClientListItem => ({
    id,
    client_id: `cid-${id}`,
    name: `client ${id}`,
    status: 'active',
    rate_limit_rpm: 60,
    last_used_at: null,
    created_at: '2026-01-01T00:00:00Z',
    key_slots: ['primary'],
    owner_user_ref: null,
    owner_email: null,
    purpose: null,
    environment: null,
    expires_at: null,
    methods: ['key'],
  });

  const page = (items: ClientListItem[], pageIndex: number, total: number) => ({
    items,
    total,
    page: pageIndex,
    page_size: 200,
  });

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(S2sAdminService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  // ── Listing / pagination ────────────────────────────────────────────────────

  it('lists clients through the paginated walk and unwraps items', async () => {
    let result: ClientListItem[] | undefined;
    service.listClients().subscribe(r => (result = r));
    await tick();

    const req = httpMock.expectOne(r => r.url === S2S);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('200');
    req.flush(page([client('a')], 1, 1));
    await tick();

    expect(result).toEqual([client('a')]);
  });

  it('follows every page when the total exceeds one page', async () => {
    let result: ClientListItem[] | undefined;
    service.listClients().subscribe(r => (result = r));
    await tick();

    const first = httpMock.expectOne(r => r.url === S2S && r.params.get('page') === '1');
    first.flush(page([client('a')], 1, 201));
    await tick();

    // Only reached if `getAllPages` reads `page * page_size < total`
    // correctly; an off-by-one here silently truncates every admin catalog to
    // its first 200 rows, which looks like working software.
    const second = httpMock.expectOne(r => r.url === S2S && r.params.get('page') === '2');
    second.flush(page([client('b')], 2, 201));
    await tick();

    expect(result).toEqual([client('a'), client('b')]);
  });

  it('omits the status filter entirely when none is given', async () => {
    service.listClients().subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === S2S);
    expect(req.request.params.has('status')).toBe(false);
    req.flush(page([], 1, 0));
    await tick();
  });

  it('passes the status filter through when given', async () => {
    service.listClients('disabled').subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === S2S);
    expect(req.request.params.get('status')).toBe('disabled');
    req.flush(page([], 1, 0));
    await tick();
  });

  // ── Client CRUD ─────────────────────────────────────────────────────────────

  it('creates a client', async () => {
    service.createClient({ client_id: 'cid-1', name: 'billing' }).subscribe();
    await tick();
    const req = httpMock.expectOne(S2S);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ client_id: 'cid-1', name: 'billing' });
    req.flush({});
    await tick();
  });

  it('gets and deletes a client by id', async () => {
    service.getClient('c1').subscribe();
    await tick();
    const get = httpMock.expectOne(`${S2S}/c1`);
    expect(get.request.method).toBe('GET');
    get.flush({});
    await tick();

    service.deleteClient('c1').subscribe();
    await tick();
    const del = httpMock.expectOne(`${S2S}/c1`);
    expect(del.request.method).toBe('DELETE');
    del.flush(null);
    await tick();
  });

  it('carries row_version in the PATCH body, not an If-Match header', async () => {
    // Pins actual behaviour rather than the assumption: `ApiService.patch`
    // only sends `If-Match` when passed its optional `etag` argument, and this
    // service does not pass one — the optimistic-concurrency token travels in
    // `UpdateClientBody.row_version` instead. Anyone "fixing" this to send the
    // header must change the backend contract deliberately, not by accident.
    service.updateClient('c1', { name: 'renamed', row_version: 7 }).subscribe();
    await tick();
    const req = httpMock.expectOne(`${S2S}/c1`);
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ name: 'renamed', row_version: 7 });
    expect(req.request.headers.has('If-Match')).toBe(false);
    req.flush({});
    await tick();
  });

  // ── Keys ────────────────────────────────────────────────────────────────────

  it('generates a key under the client-scoped keys route', async () => {
    service.generateKey('c1', { slot: 'secondary' }).subscribe();
    await tick();
    const req = httpMock.expectOne(`${S2S}/c1/keys`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ slot: 'secondary' });
    req.flush({});
    await tick();
  });

  it('revokes a key by slot', async () => {
    service.revokeKey('c1', 'primary').subscribe();
    await tick();
    const req = httpMock.expectOne(`${S2S}/c1/keys/primary`);
    expect(req.request.method).toBe('DELETE');
    req.flush(null);
    await tick();
  });

  // ── Permissions ─────────────────────────────────────────────────────────────

  it('lists, sets and deletes permissions on the client-scoped routes', async () => {
    service.listPermissions('c1').subscribe();
    await tick();
    const list = httpMock.expectOne(`${S2S}/c1/permissions`);
    expect(list.request.method).toBe('GET');
    list.flush([]);
    await tick();

    service.setPermission('c1', { entity_name: 'contact', can_read: true }).subscribe();
    await tick();
    const set = httpMock.expectOne(`${S2S}/c1/permissions`);
    expect(set.request.method).toBe('POST');
    expect(set.request.body).toEqual({ entity_name: 'contact', can_read: true });
    set.flush({});
    await tick();

    service.deletePermission('c1', 'contact').subscribe();
    await tick();
    const del = httpMock.expectOne(`${S2S}/c1/permissions/contact`);
    expect(del.request.method).toBe('DELETE');
    del.flush(null);
    await tick();
  });

  // ── Logs ────────────────────────────────────────────────────────────────────

  it('defaults the log window to limit=50 offset=0', async () => {
    service.listLogs('c1').subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === `${S2S}/c1/logs`);
    expect(req.request.params.get('limit')).toBe('50');
    expect(req.request.params.get('offset')).toBe('0');
    req.flush({ items: [], total: 0, limit: 50, offset: 0 });
    await tick();
  });

  it('passes an explicit log window through', async () => {
    service.listLogs('c1', 10, 20).subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === `${S2S}/c1/logs`);
    expect(req.request.params.get('limit')).toBe('10');
    expect(req.request.params.get('offset')).toBe('20');
    req.flush({ items: [], total: 0, limit: 10, offset: 20 });
    await tick();
  });

  // ── Cross-cutting ───────────────────────────────────────────────────────────

  it('sends session credentials on every request', async () => {
    // These are cookie-authenticated admin routes; dropping withCredentials
    // turns every call into an anonymous 401 that looks like a permissions bug.
    service.getClient('c1').subscribe();
    await tick();
    const req = httpMock.expectOne(`${S2S}/c1`);
    expect(req.request.withCredentials).toBe(true);
    req.flush({});
    await tick();
  });

  it('surfaces the backend error contract rather than a raw HttpErrorResponse', async () => {
    let error: { status: number; kind: string; message: string } | undefined;
    service.getClient('missing').subscribe({ error: e => (error = e) });
    await tick();

    httpMock.expectOne(`${S2S}/missing`).flush(
      { error: 'NotFound', message: 'no such client' },
      { status: 404, statusText: 'Not Found' },
    );
    await tick();

    expect(error?.status).toBe(404);
    expect(error?.message).toBe('no such client');
  });
});
