import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ATTOME_CONFIG } from '@attome/base';
import type { ApiError } from '@attome/base';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { MyApprovalsService } from './my-approvals.service';

describe('MyApprovalsService', () => {
  const API = 'http://localhost:7865';
  const REQ = '01900000-0000-7000-8000-0000000000a1';
  let service: MyApprovalsService;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting(), { provide: ATTOME_CONFIG, useValue: { apiUrl: API } }],
    });
    service = TestBed.inject(MyApprovalsService);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('lists the caller\'s approvals from the My Work provider, with the cursor when given', () => {
    service.list().subscribe();
    const first = http.expectOne(r => r.url === `${API}/api/v1/my-work/approvals`);
    expect(first.request.method).toBe('GET');
    expect(first.request.params.get('limit')).toBe('50');
    expect(first.request.params.has('cursor')).toBe(false);
    first.flush({ items: [], next_cursor: 'c1' });

    service.list('c1').subscribe();
    const second = http.expectOne(r => r.url === `${API}/api/v1/my-work/approvals`);
    expect(second.request.params.get('cursor')).toBe('c1');
    second.flush({ items: [] });
  });

  it('decides through the action\'s own non-admin route with the item\'s row_version', () => {
    service.decide({ key: 'approve', method: 'POST', route: `/api/v1/approvals/${REQ}/decide` }, 'approve', 3).subscribe();
    const req = http.expectOne(`${API}/api/v1/approvals/${REQ}/decide`);
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ decision: 'approve', row_version: 3 });
    req.flush({ id: REQ, status: 'approved' });
  });

  it('sends a trimmed comment, and omits a blank one', () => {
    const action = { key: 'reject', method: 'POST', route: `/api/v1/approvals/${REQ}/decide` };
    service.decide(action, 'reject', 1, '  not enough detail  ').subscribe();
    const withComment = http.expectOne(`${API}/api/v1/approvals/${REQ}/decide`);
    expect(withComment.request.body).toEqual({ decision: 'reject', row_version: 1, comment: 'not enough detail' });
    withComment.flush({ id: REQ, status: 'rejected' });

    service.decide(action, 'reject', 1, '   ').subscribe();
    const blank = http.expectOne(`${API}/api/v1/approvals/${REQ}/decide`);
    expect(blank.request.body).toEqual({ decision: 'reject', row_version: 1 });
    blank.flush({ id: REQ, status: 'rejected' });
  });

  it('refuses an action that is not a POST to an /api/v1/ route, without calling anything', () => {
    let error: ApiError | undefined;
    service.decide({ key: 'approve', method: 'POST', route: 'https://elsewhere.example/x' }, 'approve', 0)
      .subscribe({ error: e => (error = e) });
    expect(error?.kind).toBe('validation');
    service.decide({ key: 'approve', method: 'DELETE', route: `/api/v1/approvals/${REQ}/decide` }, 'approve', 0)
      .subscribe({ error: e => (error = e) });
    expect(error?.kind).toBe('validation');
  });
});
