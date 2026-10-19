import { TestBed } from '@angular/core/testing';
import { ApiService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryBackend, OfflineStore, uuidv7 } from './offline-store';
import { OFFLINE_STORE, OfflineQueueService } from './offline-queue.service';
import { SyncService, expired, nextBackoff } from './sync.service';

describe('offline', () => {
  let backend: MemoryBackend;
  let api: { post: ReturnType<typeof vi.fn> };

  function setup() {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        { provide: OFFLINE_STORE, useFactory: () => new OfflineStore(backend) },
        { provide: ApiService, useValue: api },
      ],
    });
    return {
      queue: TestBed.inject(OfflineQueueService),
      sync: TestBed.inject(SyncService),
      store: TestBed.inject(OFFLINE_STORE),
    };
  }

  beforeEach(() => {
    backend = new MemoryBackend();
    api = { post: vi.fn() };
  });

  afterEach(() => {
    vi.useRealTimers();
    TestBed.inject(SyncService).stop();
  });

  it('values are encrypted at rest', async () => {
    const { store } = setup();
    await store.putRecord('account', 'a1', { name: 'Acme Trading', phone: '+966551234567' });
    const raw = backend.data.get('records')?.get(OfflineStore.recordKey('account', 'a1'));
    expect(raw).toBeDefined();
    expect(JSON.stringify(raw)).not.toContain('Acme');
    const bytes = new Uint8Array((raw as { data: ArrayBuffer }).data);
    expect(new TextDecoder().decode(bytes)).not.toContain('Acme');
    expect(await store.getRecord('account', 'a1')).toEqual({ name: 'Acme Trading', phone: '+966551234567' });
    // The key itself is a CryptoKey that cannot be exported.
    const key = backend.data.get('meta')?.get('crypto-key') as CryptoKey;
    expect(key.extractable).toBe(false);
  });

  it('queue keeps order across reload', async () => {
    const first = setup();
    const a = await first.queue.enqueue({ kind: 'create', entity: 'task', id: uuidv7(), changed: { subject: 'One' } });
    const b = await first.queue.enqueue({ kind: 'update', entity: 'task', id: a.id, changed: { subject: 'Two' } });
    // A new app start over the same database.
    const again = setup();
    const pending = await again.queue.pending();
    expect(pending.map(op => op.seq)).toEqual([a.seq, b.seq]);
    expect(pending.map(op => op.client_op_id)).toEqual([a.client_op_id, b.client_op_id]);
    expect(pending[1].id).toBe(a.id);
    const c = await again.queue.enqueue({ kind: 'delete', entity: 'task', id: a.id });
    expect(c.seq).toBe(b.seq + 1);
  });

  it('push retried with same client_op_id', async () => {
    vi.useFakeTimers();
    const { queue, sync } = setup();
    const op = await queue.enqueue({ kind: 'update', entity: 'task', id: 't1', base_row_version: 3, changed: { status: 'done' } });
    api.post.mockImplementation((path: string) => {
      if (path === '/api/v1/offline/pull') return of({ upserts: [], removals: [], done: true });
      return api.post.mock.calls.filter(c => c[0] === '/api/v1/offline/push').length === 1
        ? throwError(() => new Error('offline'))
        : of({ results: [{ client_op_id: op.client_op_id, status: 'applied', id: 't1' }] });
    });
    sync.start('device-1');
    await vi.waitFor(() => expect(sync.lastError()).toBe('offline'));
    expect(await queue.size()).toBe(1);
    await vi.advanceTimersByTimeAsync(nextBackoff(0));
    await vi.waitFor(() => expect(sync.lastError()).toBeNull());
    const pushes = api.post.mock.calls.filter(c => c[0] === '/api/v1/offline/push');
    expect(pushes.length).toBe(2);
    expect(pushes[0][1].ops[0].client_op_id).toBe(op.client_op_id);
    expect(pushes[1][1].ops[0].client_op_id).toBe(op.client_op_id);
    expect(pushes[1][1].ops[0].seq).toBeUndefined();
    expect(await queue.size()).toBe(0);
  });

  it('expired device wipes', async () => {
    const { store, queue, sync } = setup();
    const now = Date.UTC(2026, 9, 19);
    await store.put('meta', 'lastSyncAt', now - 8 * 86_400_000);
    await store.put('meta', 'maxDaysOffline', 7);
    await store.putRecord('account', 'a1', { name: 'Acme' });
    await queue.enqueue({ kind: 'delete', entity: 'account', id: 'a1' });
    sync.setDevice('device-1');
    expect(await sync.sync(now)).toBe(false);
    expect(await store.getRecord('account', 'a1')).toBeNull();
    expect(await queue.size()).toBe(0);
    expect(api.post).not.toHaveBeenCalled();
    expect(expired(now, 7, now + 6 * 86_400_000)).toBe(false);
    expect(expired(null, 7, now)).toBe(false);
    expect(nextBackoff(0)).toBe(2000);
    expect(nextBackoff(240_000)).toBe(300_000);
  });
});
