import { HttpClient, HttpErrorResponse, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { firstValueFrom } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { offlineDataInterceptor, offlineRoute, schemaKey } from './offline-data.interceptor';
import { OFFLINE_STORE, OfflineQueueService } from './offline-queue.service';
import { MemoryBackend, OfflineStore } from './offline-store';
import { PROFILE_KEY } from './state-machine';

/** Visits must have a reason when the outcome is `lost`. */
const SCHEMA: EntitySchema = {
  id: 'e1', name: 'Visit', plural_name: 'Visits', relationships: [],
  fields: [
    { id: 'f1', entity_id: 'e1', name: 'outcome', display_name: 'Outcome', field_type: 'text', options: null, sort_order: 0, is_required: false },
    { id: 'f2', entity_id: 'e1', name: 'reason', display_name: 'Reason', field_type: 'text', options: null, sort_order: 1, is_required: false },
  ],
  business_rules: [{
    name: 'reason_when_lost', display_name: 'A lost visit needs a reason',
    condition: { all: [{ field: 'outcome', op: 'eq', value: 'lost' }, { field: 'reason', op: 'is_empty' }] } as never,
    policies: [{ type: 'error', field: 'reason', message: 'Say why it was lost' }],
  }],
};

describe('offline data path (B18-T8)', () => {
  let http: HttpClient;
  let store: OfflineStore;
  let online = true;

  beforeEach(async () => {
    online = true;
    Object.defineProperty(navigator, 'onLine', { configurable: true, get: () => online });
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([offlineDataInterceptor])),
        provideHttpClientTesting(),
        { provide: OFFLINE_STORE, useFactory: () => new OfflineStore(new MemoryBackend()) },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
    http = TestBed.inject(HttpClient);
    store = TestBed.inject(OFFLINE_STORE);
    await store.put('meta', PROFILE_KEY, {
      bundle_version: '1', max_days_offline: 7,
      entities: [{ entity: 'visit', state_model: null, autonumber_fields: ['visit_no'] }],
    });
    await store.put('meta', schemaKey('visit'), SCHEMA);
    await store.putRecord('visit', 'v1', { id: 'v1', row_version: 3, outcome: 'won', reason: null });
  });

  afterEach(() => TestBed.inject(HttpTestingController).verify());

  it('reads the routes it serves', () => {
    expect(offlineRoute('GET', '/api/v1/visit/v1', null)).toEqual({ kind: 'get', entity: 'visit', id: 'v1' });
    expect(offlineRoute('POST', '/api/v1/query/execute', { entity: 'visit' })).toEqual({ kind: 'list', entity: 'visit' });
    expect(offlineRoute('POST', '/api/v1/auth/login', {})).toBeNull();
    expect(offlineRoute('GET', '/health', null)).toBeNull();
  });

  it('offline, a route the device does not hold fails as the network did', async () => {
    online = false;
    const failed = await firstValueFrom(http.get('/api/v1/admin/entities')).catch((e: HttpErrorResponse) => e);
    expect((failed as HttpErrorResponse).status).toBe(0);
  });

  it('offline get served from store', async () => {
    online = false;
    const record = await firstValueFrom(http.get<{ id: string; data: Record<string, unknown>; row_version: number }>('/api/v1/visit/v1'));
    expect(record.id).toBe('v1');
    expect(record.row_version).toBe(3);
    expect(record.data['outcome']).toBe('won');
    const list = await firstValueFrom(http.post<{ data: { records: unknown[]; total: number } }>(
      '/api/v1/query/execute', { entity: 'visit', page: 1, page_size: 50, filters: [{ field: 'outcome', op: 'eq', value: 'won' }] }));
    expect(list.data.total).toBe(1);
    const missing = await firstValueFrom(http.get('/api/v1/visit/nope')).catch((e: HttpErrorResponse) => e);
    expect((missing as HttpErrorResponse).status).toBe(404);
    expect((missing as HttpErrorResponse).error.error).toBe('not_on_device');
  });

  it('offline create runs rules', async () => {
    online = false;
    const refused = await firstValueFrom(http.post('/api/v1/visit', { outcome: 'lost' })).catch((e: HttpErrorResponse) => e);
    expect((refused as HttpErrorResponse).status).toBe(422);
    expect((refused as HttpErrorResponse).error.error).toBe('validation_error');
    expect((refused as HttpErrorResponse).error.details).toEqual([{ field: 'reason', code: 'rule_violation', message: 'Say why it was lost' }]);
    expect(await TestBed.inject(OfflineQueueService).size()).toBe(0);

    const made = await firstValueFrom(http.post<{ id: string }>('/api/v1/visit', { outcome: 'lost', reason: 'price' }));
    const queued = await TestBed.inject(OfflineQueueService).pending();
    expect(queued).toHaveLength(1);
    expect(queued[0]).toMatchObject({ kind: 'create', entity: 'visit', id: made.id, changed: { outcome: 'lost', reason: 'price' } });
  });

  it('pending number label', async () => {
    online = false;
    const made = await firstValueFrom(http.post<{ id: string; data: Record<string, unknown> }>('/api/v1/visit', { outcome: 'won' }));
    expect(made.data['visit_no']).toBe('offline.pendingNumber');
    // The queued create carries only what the person entered.
    const [op] = await TestBed.inject(OfflineQueueService).pending();
    expect(op.changed).toEqual({ outcome: 'won' });
  });

  it('online it passes through and keeps the schema', async () => {
    const answer = firstValueFrom(http.get('/api/v1/schema/visit'));
    TestBed.inject(HttpTestingController).expectOne('/api/v1/schema/visit').flush({ ...SCHEMA, name: 'Visit v2' });
    await answer;
    // The store encrypts on write (WebCrypto), so the copy lands a little later.
    let kept: EntitySchema | null = null;
    for (let i = 0; i < 50 && kept?.name !== 'Visit v2'; i++) {
      await new Promise(r => setTimeout(r, 10));
      kept = await store.get<EntitySchema>('meta', schemaKey('visit'));
    }
    expect(kept?.name).toBe('Visit v2');
  });
});
