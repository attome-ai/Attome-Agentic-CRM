import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  DataProtectionAdminService,
  type FulfillErasurePending,
  type FulfillErasureResult,
} from './data-protection-admin.service';

/** The SDK sends after a promise turn (Y9-T3). */
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 0));

describe('DataProtectionAdminService', () => {
  let service: DataProtectionAdminService;
  let httpMock: HttpTestingController;

  const API = 'http://localhost:7865';
  const DSR = `${API}/api/v1/admin/dsr/requests`;
  const HOLDS = `${API}/api/v1/admin/legal-holds`;
  const DOMAINS = `${API}/api/v1/admin/governance/domains`;

  const scopes = [{ entity_logicalname: 'contact', match_attribute: 'emailaddress' }];

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: API } },
      ],
    });
    service = TestBed.inject(DataProtectionAdminService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  // ── DSR listing ─────────────────────────────────────────────────────────────

  it('lists DSR requests with 1-based paging', async () => {
    // Deliberately pinned: every offset list is 1-based (D-793). Sending 0
    // would be clamped to page 1, so a pager built on it repeats a page of
    // subject-rights requests, which is a compliance artefact, not a cosmetic list.
    service.listDsrRequests().subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === DSR);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('50');
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
    await tick();
  });

  it('omits status and request_type when not supplied', async () => {
    service.listDsrRequests().subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === DSR);
    expect(req.request.params.has('status')).toBe(false);
    expect(req.request.params.has('request_type')).toBe(false);
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
    await tick();
  });

  it('passes status, request_type and an explicit page window through', async () => {
    service.listDsrRequests('open', 'erasure', 2, 25).subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === DSR);
    expect(req.request.params.get('status')).toBe('open');
    expect(req.request.params.get('request_type')).toBe('erasure');
    expect(req.request.params.get('page')).toBe('2');
    expect(req.request.params.get('page_size')).toBe('25');
    req.flush({ items: [], total: 0, page: 2, page_size: 25 });
    await tick();
  });

  it('creates a DSR request', async () => {
    service.createDsrRequest({ subject_reference: 'a@b.test', request_type: 'access' }).subscribe();
    await tick();
    const req = httpMock.expectOne(DSR);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ subject_reference: 'a@b.test', request_type: 'access' });
    req.flush({});
    await tick();
  });

  // ── Fulfilment ──────────────────────────────────────────────────────────────

  it('fulfils access and portability on distinct routes', async () => {
    // These two take an identical body and differ only by path; a copy-paste
    // slip between them silently fulfils the wrong statutory right.
    service.fulfillAccess('d1', { scopes, admin_override: false }).subscribe();
    await tick();
    const access = httpMock.expectOne(`${DSR}/d1/fulfill-access`);
    expect(access.request.method).toBe('POST');
    access.flush({ id: 'd1', status: 'fulfilled', scopes: [] });
    await tick();

    service.fulfillPortability('d1', { scopes, admin_override: false }).subscribe();
    await tick();
    const port = httpMock.expectOne(`${DSR}/d1/fulfill-portability`);
    expect(port.request.method).toBe('POST');
    port.flush({ id: 'd1', status: 'fulfilled', scopes: [] });
    await tick();
  });

  it('carries admin_override explicitly rather than by omission', async () => {
    service.fulfillAccess('d1', { scopes, admin_override: true }).subscribe();
    await tick();
    const req = httpMock.expectOne(`${DSR}/d1/fulfill-access`);
    expect(req.request.body).toEqual({ scopes, admin_override: true });
    req.flush({ id: 'd1', status: 'fulfilled', scopes: [] });
    await tick();
  });

  it('returns an executed erasure result when erasure is not gated', async () => {
    let result: FulfillErasureResult | FulfillErasurePending | undefined;
    service.fulfillErasure('d1', { scopes }).subscribe(r => (result = r));
    await tick();

    httpMock.expectOne(`${DSR}/d1/fulfill-erasure`).flush({
      id: 'd1',
      status: 'fulfilled',
      block_reason: null,
      erased: [{ entity_logicalname: 'contact', record_id: 'r1', key_destroyed: true }],
    });
    await tick();

    expect('approval_pending' in result!).toBe(false);
    expect((result as FulfillErasureResult).erased).toHaveLength(1);
  });

  it('returns an approval-pending envelope when erasure is four-eyes gated', async () => {
    // D-269: the same call returns one of two disjoint shapes. A caller that
    // assumes the executed shape reports "records erased" when nothing was
    // erased and an approval is merely queued — the worst possible direction
    // to be wrong about an erasure.
    let result: FulfillErasureResult | FulfillErasurePending | undefined;
    service.fulfillErasure('d1', { scopes }).subscribe(r => (result = r));
    await tick();

    httpMock.expectOne(`${DSR}/d1/fulfill-erasure`).flush({
      approval_pending: true,
      approval_request_id: 'ar-7',
    });
    await tick();

    expect('approval_pending' in result!).toBe(true);
    expect((result as FulfillErasurePending).approval_request_id).toBe('ar-7');
  });

  // ── Legal holds ─────────────────────────────────────────────────────────────

  it('defaults the legal-hold listing to active holds', async () => {
    service.listLegalHolds().subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === HOLDS);
    expect(req.request.params.get('status')).toBe('active');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.has('entity_logicalname')).toBe(false);
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
    await tick();
  });

  it('can list released holds filtered by entity', async () => {
    service.listLegalHolds('released', 'contact').subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === HOLDS);
    expect(req.request.params.get('status')).toBe('released');
    expect(req.request.params.get('entity_logicalname')).toBe('contact');
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
    await tick();
  });

  it('places a hold, allowing an entity-wide hold with no record_id', async () => {
    service.placeLegalHold({ entity_logicalname: 'contact', matter_reference: 'M-1' }).subscribe();
    await tick();
    const req = httpMock.expectOne(HOLDS);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ entity_logicalname: 'contact', matter_reference: 'M-1' });
    req.flush({});
    await tick();
  });

  it('releases a hold via POST with an empty body', async () => {
    service.releaseLegalHold('h1').subscribe();
    await tick();
    const req = httpMock.expectOne(`${HOLDS}/h1/release`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({});
    req.flush({});
    await tick();
  });

  it('sends session credentials', async () => {
    service.listLegalHolds().subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === HOLDS);
    expect(req.request.withCredentials).toBe(true);
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
    await tick();
  });

  // ── Data domains (M15 Data Governance, D-413) ─────────────────────────────

  it('lists domains with 1-based paging', async () => {
    service.listDomains().subscribe();
    await tick();
    const req = httpMock.expectOne(r => r.url === DOMAINS);
    expect(req.request.method).toBe('GET');
    expect(req.request.params.get('page')).toBe('1');
    expect(req.request.params.get('page_size')).toBe('50');
    req.flush({ items: [], total: 0, page: 1, page_size: 50 });
    await tick();
  });

  it('creates a domain', async () => {
    service.createDomain({ name: 'Customer', steward_ref: 'u1' }).subscribe();
    await tick();
    const req = httpMock.expectOne(DOMAINS);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ name: 'Customer', steward_ref: 'u1' });
    req.flush({});
    await tick();
  });

  it('gets one domain by id', async () => {
    service.getDomain('d1').subscribe();
    await tick();
    const req = httpMock.expectOne(`${DOMAINS}/d1`);
    expect(req.request.method).toBe('GET');
    req.flush({});
    await tick();
  });

  it('updates a domain carrying row_version in the body, not an If-Match header', async () => {
    // governance_admin.rs::update_domain's OCC contract is a body field, not
    // the header-based ETag convention `patch()`'s `etag` param produces —
    // calling with the default (no etag) is the correct usage here.
    service.updateDomain('d1', { name: 'renamed', row_version: 3 }).subscribe();
    await tick();
    const req = httpMock.expectOne(`${DOMAINS}/d1`);
    expect(req.request.method).toBe('PATCH');
    expect(req.request.body).toEqual({ name: 'renamed', row_version: 3 });
    expect(req.request.headers.has('If-Match')).toBe(false);
    req.flush({});
    await tick();
  });

  it('assigns entities to a domain', async () => {
    service.assignEntities('d1', ['contact', 'account']).subscribe();
    await tick();
    const req = httpMock.expectOne(`${DOMAINS}/d1/entities`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ entity_logicalnames: ['contact', 'account'] });
    req.flush([]);
    await tick();
  });

  it('unassigns an entity, URL-encoding its logicalname', async () => {
    service.unassignEntity('d1', 'xrm contact/weird').subscribe();
    await tick();
    const req = httpMock.expectOne(`${DOMAINS}/d1/entities/${encodeURIComponent('xrm contact/weird')}`);
    expect(req.request.method).toBe('DELETE');
    req.flush(null);
    await tick();
  });

  it('fetches the accountability report', async () => {
    service.getDomainReport('d1').subscribe();
    await tick();
    const req = httpMock.expectOne(`${DOMAINS}/d1/report`);
    expect(req.request.method).toBe('GET');
    expect(req.request.withCredentials).toBe(true);
    req.flush({
      domain_id: 'd1', domain_name: 'Customer', steward_ref: null, deputy_ref: null,
      entities: [], classification_breakdown: { general: 0, personal: 0, sensitive_special_category: 0 },
      open_issues: [], legal_holds: [], dsr_requests: [], last_review_date: null,
    });
    await tick();
  });
});
