import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { firstValueFrom } from 'rxjs';
import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import { ApiService, CHANGESET_HEADER, changesetRefusalCode } from './api.service';
import { ATTOME_CONFIG } from './config';
import type { ApiError } from './types';

describe('ApiService', () => {
  let service: ApiService;
  let httpMock: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      ],
    });
    service = TestBed.inject(ApiService);
    httpMock = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpMock.verify());

  it('prefixes requests with the configured apiUrl', () => {
    service.get('/api/v1/foo').subscribe();
    const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
    expect(req.request.withCredentials).toBe(true);
    req.flush({});
  });

  describe('getIfChanged (Y14-T2)', () => {
    it('returns the body and its ETag, sending no If-None-Match without one', async () => {
      const result = firstValueFrom(service.getIfChanged<{ a: number }>('/api/v1/plan', null));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/plan');
      expect(req.request.headers.has('If-None-Match')).toBe(false);
      req.flush({ a: 1 }, { headers: { ETag: '"v1"' } });
      expect(await result).toEqual({ body: { a: 1 }, etag: '"v1"' });
    });

    it('answers a 304 as an unchanged, bodyless result', async () => {
      const result = firstValueFrom(service.getIfChanged('/api/v1/plan', '"v1"'));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/plan');
      expect(req.request.headers.get('If-None-Match')).toBe('"v1"');
      req.flush(null, { status: 304, statusText: 'Not Modified' });
      expect(await result).toEqual({ body: null, etag: '"v1"' });
    });
  });

  describe('patch / If-Match', () => {
    it('sends no If-Match header when no row_version is given', () => {
      service.patch('/api/v1/foo/1', { name: 'x' }).subscribe();
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo/1');
      expect(req.request.headers.has('If-Match')).toBe(false);
      req.flush({});
    });

    it('sends a quoted If-Match header when a row_version is given', () => {
      service.patch('/api/v1/foo/1', { name: 'x' }, 3).subscribe();
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo/1');
      expect(req.request.headers.get('If-Match')).toBe('"3"');
      req.flush({});
    });
  });

  // NGB-2.5 / OD-4b — the typed `{ idempotencyKey }` option replaces the raw
  // header bag on every mutating call.
  describe('write options (NGB-2.5)', () => {
    const URL = 'http://localhost:7865/api/v1/foo';

    it('post sends the idempotency key as x-idempotency-key, with credentials', () => {
      service.post('/api/v1/foo', { a: 1 }, { idempotencyKey: 'k-1' }).subscribe();
      const req = httpMock.expectOne(URL);
      expect(req.request.headers.get('x-idempotency-key')).toBe('k-1');
      expect(req.request.withCredentials).toBe(true);
      req.flush({});
    });

    it('post sends no idempotency header when none is given', () => {
      service.post('/api/v1/foo', { a: 1 }).subscribe();
      const req = httpMock.expectOne(URL);
      expect(req.request.headers.has('x-idempotency-key')).toBe(false);
      req.flush({});
    });

    it('put, patch and delete all carry the option', () => {
      service.put('/api/v1/foo', { a: 1 }, { idempotencyKey: 'k-put' }).subscribe();
      const putReq = httpMock.expectOne(r => r.url === URL && r.method === 'PUT');
      expect(putReq.request.headers.get('x-idempotency-key')).toBe('k-put');
      putReq.flush({});

      service.patch('/api/v1/foo', { a: 2 }, 7, { idempotencyKey: 'k-patch' }).subscribe();
      const patchReq = httpMock.expectOne(r => r.url === URL && r.method === 'PATCH');
      expect(patchReq.request.headers.get('x-idempotency-key')).toBe('k-patch');
      expect(patchReq.request.headers.get('If-Match')).toBe('"7"');
      patchReq.flush({});

      service.delete('/api/v1/foo', { idempotencyKey: 'k-del' }).subscribe();
      const deleteReq = httpMock.expectOne(r => r.url === URL && r.method === 'DELETE');
      expect(deleteReq.request.headers.get('x-idempotency-key')).toBe('k-del');
      deleteReq.flush(null);
    });

    it('sends a duplicate reason as Attome-Duplicate-Reason (A15-T4)', () => {
      service.post('/api/v1/foo', { a: 1 }, { duplicateReason: 'second branch' }).subscribe();
      const req = httpMock.expectOne(URL);
      expect(req.request.headers.get('Attome-Duplicate-Reason')).toBe('second branch');
      req.flush({});
    });
  });

  describe('getAllPages', () => {
    const LIST = 'http://localhost:7865/api/v1/things';
    const page = (items: string[], pageNo: number, total: number, pageSize = 200) =>
      ({ items, total, page: pageNo, page_size: pageSize });
    const expectPage = (pageNo: number) =>
      httpMock.expectOne(r => r.url === LIST && r.params.get('page') === String(pageNo));

    it('walks every page and accumulates the items in order', () => {
      let result: string[] | undefined;
      service.getAllPages<string>('/api/v1/things').subscribe(r => (result = r));

      expectPage(1).flush(page(['a'], 1, 201));
      expectPage(2).flush(page(['b'], 2, 201));

      expect(result).toEqual(['a', 'b']);
    });

    it('fails before the second request when the reported total exceeds the ceiling', async () => {
      const promise = firstValueFrom(service.getAllPages<string>('/api/v1/things', {}, 200, 300));

      expectPage(1).flush(page(['a'], 1, 301));
      // The ceiling is read off page 1's `total`, so the remaining round-trips
      // never go out — that is the whole point of the bound (F-012).
      httpMock.expectNone(r => r.url === LIST && r.params.get('page') === '2');

      const error = await promise.catch((e: ApiError) => e);
      // NGB-3.3 — no hardcoded English in base any more: the error names its
      // catalog entry and `LangService.errorText` renders it in the active
      // language.
      expect(error).toMatchObject({ status: 0, kind: 'validation', code: 'too_many_pages' });
      expect((error as ApiError).message).toBe('');
    });

    it('loads a catalog that sits exactly on the ceiling', () => {
      let result: string[] | undefined;
      service.getAllPages<string>('/api/v1/things', {}, 2, 4).subscribe(r => (result = r));

      expectPage(1).flush(page(['a', 'b'], 1, 4, 2));
      expectPage(2).flush(page(['c', 'd'], 2, 4, 2));

      expect(result).toEqual(['a', 'b', 'c', 'd']);
    });

    it('stops instead of looping when a response reports page_size 0', () => {
      let result: string[] | undefined;
      service.getAllPages<string>('/api/v1/things').subscribe(r => (result = r));

      // `page * 0 < total` would be true forever; httpMock.verify() in
      // afterEach is what catches a regression here.
      expectPage(1).flush(page(['a'], 1, 99, 0));

      expect(result).toEqual(['a']);
    });

    it('starts the walk at the endpoint base and counts pages relative to it', () => {
      // Every endpoint is one-based (D-347, D-793): page 1 is the first page, so
      // `total` 3 over `page_size` 2 is exactly two pages — 1 and 2, never a page 0.
      let result: string[] | undefined;
      service.getAllPages<string>('/api/v1/things', {}, 2, 4).subscribe(r => (result = r));

      httpMock.expectNone(r => r.url === LIST && r.params.get('page') === '0');
      expectPage(1).flush(page(['a', 'b'], 1, 3, 2));
      expectPage(2).flush(page(['c'], 2, 3, 2));

      expect(result).toEqual(['a', 'b', 'c']);
    });

    it('does not re-request the last page of a one-based endpoint', () => {
      // Zero-based arithmetic ((page + 1) * size < total) would read page 2 of 2
      // as "2 * 2 < 4 -> keep going" and walk off the end of the list.
      let result: string[] | undefined;
      service.getAllPages<string>('/api/v1/things', {}, 2, 4).subscribe(r => (result = r));

      expectPage(1).flush(page(['a', 'b'], 1, 4, 2));
      expectPage(2).flush(page(['c', 'd'], 2, 4, 2));

      expect(result).toEqual(['a', 'b', 'c', 'd']);
      httpMock.verify(); // a third request would fail here
    });

    it('resumes from the page the server says it served, not the one requested', () => {
      // A handler that clamps an out-of-range page reports the clamped number.
      // Following `res.page` is what keeps the walk contiguous — resuming from
      // the requested page instead would re-read page 1 forever.
      let result: string[] | undefined;
      service.getAllPages<string>('/api/v1/things', {}, 2, 6).subscribe(r => (result = r));

      expectPage(1).flush(page(['a', 'b'], 1, 6, 2));
      expectPage(2).flush(page(['c', 'd'], 2, 6, 2));
      expectPage(3).flush(page(['e', 'f'], 3, 6, 2));

      expect(result).toEqual(['a', 'b', 'c', 'd', 'e', 'f']);
    });

    it('accumulates into a fresh array on every subscription', () => {
      const all$ = service.getAllPages<string>('/api/v1/things');
      const results: string[][] = [];

      all$.subscribe(r => results.push(r));
      expectPage(1).flush(page(['a'], 1, 1));
      all$.subscribe(r => results.push(r));
      expectPage(1).flush(page(['a'], 1, 1));

      expect(results).toEqual([['a'], ['a']]);
    });
  });

  describe('error mapping', () => {
    // NGB-2.1 — the complete AppError wire-code table
    // (attome-types/src/error.rs::into_response): status + `error`, because
    // status alone cannot disambiguate Conflict vs VersionConflict vs
    // IdempotencyConflict (all 409) or the four 503s or the four 403s. Every
    // code the enum publishes has a row; NGB-2.2's Rust guard fails if one is
    // missing here too.
    const cases: [number, string, ApiError['kind']][] = [
      [401, 'unauthorized', 'unauthorized'],
      [401, 'reauth_required', 'reauth_required'],
      [403, 'forbidden', 'forbidden'],
      [403, 'feature_hidden', 'feature_hidden'],
      [403, 'metadata_authoring_locked', 'authoring_locked'],
      [404, 'not_found', 'not_found'],
      [409, 'conflict', 'conflict'],
      [409, 'version_conflict', 'version_conflict'],
      [409, 'idempotency_conflict', 'idempotency_conflict'],
      [409, 'idempotency_outcome_unknown', 'idempotency_outcome_unknown'],
      [409, 'idempotency_replay_unavailable', 'idempotency_replay_unavailable'],
      [413, 'payload_too_large', 'payload_too_large'],
      [422, 'validation_error', 'validation'],
      [422, 'rule_violation', 'rule_violation'],
      [422, 'transition_not_allowed', 'transition_not_allowed'],
      [429, 'rate_limit_exceeded', 'rate_limited'],
      [500, 'internal_error', 'internal'],
      [503, 'feature_unavailable', 'unavailable'],
      [503, 'capability_unavailable', 'unavailable'],
      [503, 'overloaded', 'unavailable'],
      [503, 'server_timeout', 'unavailable'],
      [503, 'read_only', 'unavailable'],
    ];

    for (const [status, code, kind] of cases) {
      it(`maps HTTP ${status} + code "${code}" to kind "${kind}"`, async () => {
        const promise = firstValueFrom(service.get('/api/v1/foo'));
        const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
        req.flush({ error: code, message: 'boom' }, { status, statusText: 'Error' });

        const error = await promise.catch((e: ApiError) => e);
        expect(error).toMatchObject({ status, kind, message: 'boom' });
        // The raw code is always kept, whatever the kind collapses to.
        expect((error as ApiError).code).toBe(code);
      });
    }

    // NGB-2.1 — the statuses that previously fell through to `unknown`.
    const statusCases: [number, ApiError['kind']][] = [
      [413, 'payload_too_large'],
      [429, 'rate_limited'],
      [503, 'unavailable'],
    ];

    for (const [status, kind] of statusCases) {
      it(`falls back to kind "${kind}" for HTTP ${status} with no body code`, async () => {
        const promise = firstValueFrom(service.get('/api/v1/foo'));
        const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
        req.flush({ message: 'boom' }, { status, statusText: 'Error' });

        const error = await promise.catch((e: ApiError) => e);
        expect(error).toMatchObject({ status, kind });
      });
    }

    // NGB-2.1 — support correlates a UI error with the server's logs.
    it('keeps request_id from the body', async () => {
      const promise = firstValueFrom(service.get('/api/v1/foo'));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
      req.flush({ error: 'internal_error', message: 'x', request_id: 'req-body' }, { status: 500, statusText: 'Error' });

      const error = await promise.catch((e: ApiError) => e);
      expect((error as ApiError).requestId).toBe('req-body');
    });

    it('falls back to the x-request-id response header when the body carries none', async () => {
      const promise = firstValueFrom(service.get('/api/v1/foo'));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
      req.flush(
        null,
        { status: 502, statusText: 'Bad Gateway', headers: { 'x-request-id': 'req-header' } },
      );

      const error = await promise.catch((e: ApiError) => e);
      expect((error as ApiError).requestId).toBe('req-header');
    });

    it('keeps the matches and hidden count of a duplicate_detected refusal (A15-T4)', async () => {
      const refused = firstValueFrom(service.post('/api/v1/contact', { phone: '1' }));
      const match = { record_id: 'r1', rule_id: 'm1', rule_name: 'Phone', score: 0.9 };
      httpMock.expectOne('http://localhost:7865/api/v1/contact').flush(
        { error: 'duplicate_detected', message: 'dup', matches: [match], hidden: 2 },
        { status: 409, statusText: 'Error' },
      );
      const err = (await refused.catch((e: ApiError) => e)) as ApiError;
      expect(err.kind).toBe('conflict');
      expect(err.code).toBe('duplicate_detected');
      expect(err.duplicates).toEqual({ matches: [match], hidden: 2 });
    });

    it('keeps rule_id on a rule_violation only', async () => {
      const violation = firstValueFrom(service.get('/api/v1/foo'));
      httpMock.expectOne('http://localhost:7865/api/v1/foo')
        .flush(
          { error: 'rule_violation', message: 'rule violation: nope', rule_id: 'rule-7' },
          { status: 422, statusText: 'Error' },
        );
      expect(((await violation.catch((e: ApiError) => e)) as ApiError).ruleId).toBe('rule-7');

      const other = firstValueFrom(service.get('/api/v1/foo'));
      httpMock.expectOne('http://localhost:7865/api/v1/foo')
        .flush({ error: 'conflict', message: 'x', rule_id: 'rule-7' }, { status: 409, statusText: 'Error' });
      const err = (await other.catch((e: ApiError) => e)) as ApiError;
      expect(err.kind).toBe('conflict');
      expect(err.ruleId).toBeUndefined();
    });

    it('keeps field, rule_name, effect and details of a field_locked refusal (D-789)', async () => {
      const promise = firstValueFrom(service.patch('/api/v1/deal/1', { amount: 5 }, 3));
      httpMock.expectOne('http://localhost:7865/api/v1/deal/1').flush(
        {
          error: 'field_locked', message: "'amount' is locked by the rule 'Closed deals' and cannot be changed",
          field: 'amount', rule_id: 'rule-9', rule_name: 'Closed deals', effect: 'disabled',
          details: { fields: [{ field: 'amount', rule_id: 'rule-9', rule_name: 'Closed deals', effect: 'disabled' }] },
        },
        { status: 422, statusText: 'Error' },
      );
      const err = (await promise.catch((e: ApiError) => e)) as ApiError;
      expect(err.kind).toBe('validation');
      expect(err.code).toBe('field_locked');
      expect(err.field).toBe('amount');
      expect(err.ruleId).toBe('rule-9');
      expect(err.ruleName).toBe('Closed deals');
      expect(err.effect).toBe('disabled');
      expect(err.details).toEqual({
        fields: [{ field: 'amount', rule_id: 'rule-9', rule_name: 'Closed deals', effect: 'disabled' }],
      });
    });

    it('keeps the details of a rule_violation and leaves the new members unset when absent', async () => {
      const violation = firstValueFrom(service.get('/api/v1/foo'));
      httpMock.expectOne('http://localhost:7865/api/v1/foo').flush(
        { error: 'rule_violation', message: 'nope', rule_id: 'r', details: { field: 'amount', rules: [] } },
        { status: 422, statusText: 'Error' },
      );
      const err = (await violation.catch((e: ApiError) => e)) as ApiError;
      expect(err.details).toEqual({ field: 'amount', rules: [] });
      expect(err.field).toBeUndefined();

      const plain = firstValueFrom(service.get('/api/v1/foo'));
      httpMock.expectOne('http://localhost:7865/api/v1/foo')
        .flush({ error: 'not_found', message: 'x' }, { status: 404, statusText: 'Error' });
      const nf = (await plain.catch((e: ApiError) => e)) as ApiError;
      expect(nf.field).toBeUndefined();
      expect(nf.ruleName).toBeUndefined();
      expect(nf.effect).toBeUndefined();
      expect(nf.details).toBeUndefined();
    });

    it('maps reauth_required with its code, operation and acceptable factors (D-510)', async () => {
      const promise = firstValueFrom(service.post('/api/v1/auth/api-keys', { name: 'k' }));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/auth/api-keys');
      req.flush(
        {
          error: 'reauth_required',
          message: 're-authentication is required for this operation',
          operation: 'api_key_create',
          acceptable_factors: ['password', 'federated'],
          request_id: 'req-1',
        },
        { status: 401, statusText: 'Unauthorized' },
      );

      const error = await promise.catch((e: ApiError) => e);
      expect(error).toEqual({
        status: 401,
        kind: 'reauth_required',
        code: 'reauth_required',
        message: 're-authentication is required for this operation',
        // NGB-2.1 — the body's request_id is kept so support can correlate.
        requestId: 'req-1',
        operation: 'api_key_create',
        acceptableFactors: ['password', 'federated'],
      });
    });

    it('keeps no step-up fields on any other error', async () => {
      const promise = firstValueFrom(service.get('/api/v1/foo'));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
      req.flush(
        { error: 'unauthorized', message: 'no', operation: 'api_key_create', acceptable_factors: ['password'] },
        { status: 401, statusText: 'Unauthorized' },
      );

      const error = await promise.catch((e: ApiError) => e);
      expect(error).toEqual({ status: 401, kind: 'unauthorized', code: 'unauthorized', message: 'no' });
    });

    it('falls back to status-based classification when the body has no recognized error code', async () => {
      const promise = firstValueFrom(service.get('/api/v1/foo'));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
      req.flush({ message: 'boom' }, { status: 404, statusText: 'Error' });

      const error = await promise.catch((e: ApiError) => e);
      expect(error).toMatchObject({ status: 404, kind: 'not_found' });
    });

    it('falls back to "unknown" for an unrecognized status with no body code', async () => {
      const promise = firstValueFrom(service.get('/api/v1/foo'));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
      req.flush(null, { status: 418, statusText: 'Error' });

      const error = await promise.catch((e: ApiError) => e);
      expect((error as ApiError).kind).toBe('unknown');
    });

    // NGB-2.3 — the default message is deliberately empty. Anything else would
    // be invented English prose reaching a possibly-Arabic UI; the caller
    // renders `LangService.errorText(err)` instead, which is language-correct
    // for every kind. (The old default was 'An unexpected error occurred'.)
    it('leaves the message empty when the server sends none', async () => {
      const promise = firstValueFrom(service.get('/api/v1/foo'));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
      req.flush(null, { status: 500, statusText: 'Error' });

      const error = await promise.catch((e: ApiError) => e);
      expect((error as ApiError).message).toBe('');
      expect((error as ApiError).kind).toBe('internal');
    });

    it('never surfaces HttpErrorResponse.message, which embeds the request URL', async () => {
      const promise = firstValueFrom(service.get('/api/v1/foo'));
      const req = httpMock.expectOne('http://localhost:7865/api/v1/foo');
      // status 0 — connection refused, no JSON body at all.
      req.error(new ProgressEvent('error'), { status: 0, statusText: 'Unknown Error' });

      const error = (await promise.catch((e: ApiError) => e)) as ApiError;
      expect(error.status).toBe(0);
      expect(error.kind).toBe('unknown');
      expect(error.message).toBe('');
    });
  });
  // Solution 7 (D-785) — the picked changeset rides every mutating request.
  describe('changeset header', () => {
    const URL = 'http://localhost:7865/api/v1/admin/entities';

    it('sends no X-Attome-Changeset until one is set', () => {
      service.post('/api/v1/admin/entities', {}).subscribe();
      const req = httpMock.expectOne(URL);
      expect(req.request.headers.has(CHANGESET_HEADER)).toBe(false);
      req.flush({});
    });

    it('sends the set changeset on post, put, patch and delete, never on get', () => {
      service.setChangeset('0199aaaa-0000-7000-8000-000000000001');
      expect(service.activeChangeset()).toBe('0199aaaa-0000-7000-8000-000000000001');

      service.post('/api/v1/admin/entities', {}).subscribe();
      service.put('/api/v1/admin/entities', {}).subscribe();
      service.patch('/api/v1/admin/entities', {}, 2).subscribe();
      service.delete('/api/v1/admin/entities').subscribe();
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const req = httpMock.expectOne(r => r.url === URL && r.method === method);
        expect(req.request.headers.get(CHANGESET_HEADER)).toBe('0199aaaa-0000-7000-8000-000000000001');
        req.flush(method === 'DELETE' ? null : {});
      }

      service.get('/api/v1/admin/entities').subscribe();
      const get = httpMock.expectOne(r => r.url === URL && r.method === 'GET');
      expect(get.request.headers.has(CHANGESET_HEADER)).toBe(false);
      get.flush({});
    });

    it('clearing (null or blank) stops sending it', () => {
      service.setChangeset('0199aaaa-0000-7000-8000-000000000001');
      service.setChangeset('   ');
      expect(service.activeChangeset()).toBeNull();
      service.post('/api/v1/admin/entities', {}).subscribe();
      const req = httpMock.expectOne(URL);
      expect(req.request.headers.has(CHANGESET_HEADER)).toBe(false);
      req.flush({});
    });
  });

  describe('changeset refusals', () => {
    const cases: [string, string][] = [
      ['changeset_required', 'conflict: changeset_required: this metadata write must be recorded in an open changeset'],
      ['changeset_ambiguous', 'conflict: changeset_ambiguous: you have more than one open changeset'],
      ['changeset_not_open', 'conflict: changeset_not_open: the changeset does not exist'],
      ['layer_mismatch', 'conflict: layer_mismatch: this object is owned by another layer'],
      ['hard_delete_not_recordable', 'conflict: hard_delete_not_recordable: a hard delete cannot be recorded'],
    ];

    for (const [code, message] of cases) {
      it(`lifts "${code}" out of a 409 conflict message, keeping kind conflict`, async () => {
        const promise = firstValueFrom(service.patch('/api/v1/admin/entities/1', {}, 1));
        httpMock.expectOne('http://localhost:7865/api/v1/admin/entities/1')
          .flush({ error: 'conflict', message }, { status: 409, statusText: 'Conflict' });
        const error = (await promise.catch((e: ApiError) => e)) as ApiError;
        expect(error.kind).toBe('conflict');
        expect(error.code).toBe(code);
        // The prose stays for screens that print `message`, minus the plumbing.
        expect(error.message).not.toContain(`${code}:`);
        expect(error.message).not.toMatch(/^conflict:/);
        expect(error.message.length).toBeGreaterThan(0);
      });
    }

    it('leaves an ordinary conflict alone', async () => {
      const promise = firstValueFrom(service.post('/api/v1/foo', {}));
      httpMock.expectOne('http://localhost:7865/api/v1/foo')
        .flush({ error: 'conflict', message: 'conflict: name already taken' }, { status: 409, statusText: 'Conflict' });
      const error = (await promise.catch((e: ApiError) => e)) as ApiError;
      expect(error.code).toBe('conflict');
      expect(error.message).toBe('conflict: name already taken');
    });

    it('parses the prefix with or without the conflict: lead', () => {
      expect(changesetRefusalCode('layer_mismatch: owned by platform')).toBe('layer_mismatch');
      expect(changesetRefusalCode('conflict: layer_mismatch: owned by platform')).toBe('layer_mismatch');
      expect(changesetRefusalCode('conflict: something else')).toBeNull();
      expect(changesetRefusalCode(undefined)).toBeNull();
    });
  });
});
