import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { MemoryBackend, OfflineStore, uuidv7 } from './offline-store';
import { OFFLINE_FILE_UPLOADER, OFFLINE_STORE, OfflineQueueService, OfflineUploadResult } from './offline-queue.service';
import { SyncStatusComponent } from './sync-status.component';
import { SyncService } from './sync.service';

describe('B18-T10 sync status and offline files', () => {
  let backend: MemoryBackend;
  let api: { post: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };
  let upload: ReturnType<typeof vi.fn<(t: unknown, f: File) => Promise<OfflineUploadResult>>>;

  beforeEach(() => {
    backend = new MemoryBackend();
    api = {
      post: vi.fn((path: string, body: { ops?: { client_op_id: string; id: string }[] }) =>
        path === '/api/v1/offline/pull'
          ? of({ upserts: [], removals: [], done: true })
          : of({ results: (body.ops ?? []).map(op => ({ client_op_id: op.client_op_id, status: 'applied', id: op.id })) })),
      get: vi.fn(() => of({ bundle_version: 'v1', max_days_offline: 30, entities: [] })),
    };
    upload = vi.fn(async () => ({ kind: 'clean', finalKey: 'files/clean/photo.jpg' }) as OfflineUploadResult);
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        { provide: OFFLINE_STORE, useFactory: () => new OfflineStore(backend) },
        { provide: ApiService, useValue: api },
        { provide: OFFLINE_FILE_UPLOADER, useValue: { upload } },
        { provide: LangService, useValue: {
          translate: (key: string, params?: Record<string, unknown>) => params ? `${key} ${JSON.stringify(params)}` : key,
        } },
      ],
    });
  });

  afterEach(() => TestBed.inject(SyncService).stop());

  it('shows queue count', async () => {
    const queue = TestBed.inject(OfflineQueueService);
    await queue.enqueue({ kind: 'create', entity: 'task', id: uuidv7(), changed: { subject: 'One' } });
    await queue.enqueue({ kind: 'create', entity: 'task', id: uuidv7(), changed: { subject: 'Two' } });
    TestBed.inject(SyncService).active.set(true);

    const fixture = TestBed.createComponent(SyncStatusComponent);
    fixture.detectChanges();
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('[data-testid="sync-status"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="sync-status-waiting"]')?.textContent).toContain('2');
  });

  it('hidden until syncing starts', () => {
    const fixture = TestBed.createComponent(SyncStatusComponent);
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).querySelector('[data-testid="sync-status"]')).toBeNull();
  });

  it('file op waits for upload', async () => {
    const queue = TestBed.inject(OfflineQueueService);
    const sync = TestBed.inject(SyncService);
    const id = uuidv7();
    const photo = new File([new Uint8Array([1, 2, 3])], 'photo.jpg', { type: 'image/jpeg' });
    await queue.enqueueWithFiles({ kind: 'create', entity: 'visit', id, changed: { subject: 'Site' } }, { photo });
    expect(await queue.size()).toBe(2);

    // The upload fails: nothing is pushed after it, and the file stays.
    upload.mockResolvedValueOnce({ kind: 'error', message: 'network' });
    sync.setDevice('device-1');
    expect(await sync.sync()).toBe(false);
    const pushed = api.post.mock.calls
      .filter(c => c[0] === '/api/v1/offline/push')
      .flatMap(c => (c[1] as { ops: { kind: string }[] }).ops);
    expect(pushed.map(op => op.kind)).toEqual([]);
    expect(await queue.size()).toBe(2);
    expect(await backend.keys('files')).toHaveLength(1);

    // Next time it uploads, the key replaces the file and both changes go.
    api.post.mockClear();
    expect(await sync.sync()).toBe(true);
    expect(upload).toHaveBeenLastCalledWith({ entityName: 'visit', recordId: id, fieldName: 'photo' }, expect.any(File));
    const ops = api.post.mock.calls
      .filter(c => c[0] === '/api/v1/offline/push')
      .flatMap(c => (c[1] as { ops: Record<string, unknown>[] }).ops);
    expect(ops.map(op => op['kind'])).toEqual(['create', 'update']);
    expect(ops[1]['changed']).toEqual({ photo: 'files/clean/photo.jpg' });
    expect(ops[1]['files']).toBeUndefined();
    expect(await queue.size()).toBe(0);
    expect(await backend.keys('files')).toHaveLength(0);
    expect(queue.waiting()).toBe(0);
  });

  it('a rejected file is a problem and drops the change', async () => {
    const queue = TestBed.inject(OfflineQueueService);
    const sync = TestBed.inject(SyncService);
    const photo = new File([new Uint8Array([9])], 'bad.exe');
    await queue.enqueueWithFiles(
      { kind: 'update', entity: 'visit', id: uuidv7(), changed: { note: 'x' } }, { photo });
    upload.mockResolvedValueOnce({ kind: 'rejected', message: 'infected' });
    sync.setDevice('device-1');
    expect(await sync.sync()).toBe(true);
    expect(sync.problems()[0].result.code).toBe('file_rejected');
    expect(await queue.size()).toBe(0);
    expect(await backend.keys('files')).toHaveLength(0);
  });
});
