import { EnvironmentInjector, Injectable, InjectionToken, inject, signal } from '@angular/core';
import { IndexedDbBackend, MemoryBackend, OfflineStore, uuidv7 } from './offline-store';

/** The device's store; IndexedDB when the browser has it. */
export const OFFLINE_STORE = new InjectionToken<OfflineStore>('ATTOME_OFFLINE_STORE', {
  providedIn: 'root',
  factory: () => new OfflineStore(typeof indexedDB === 'undefined' ? new MemoryBackend() : new IndexedDbBackend()),
});

/** One change made offline, as `POST /api/v1/offline/push` takes it. */
export interface QueuedOp {
  seq: number;
  /** Fixed when queued; a retry sends the same one. */
  client_op_id: string;
  kind: 'create' | 'update' | 'delete';
  entity: string;
  id: string;
  base_row_version?: number;
  changed?: Record<string, unknown>;
  base_values?: Record<string, unknown>;
  /**
   * B18-T10: files captured offline for this change, by field: each names a
   * file kept in the device's `files` store until sync uploads it. Never sent
   * to the server; sync replaces each with the uploaded file's key in
   * `changed`.
   */
  files?: Record<string, string>;
}

export type NewOp = Omit<QueuedOp, 'seq' | 'client_op_id'>;

/** B18-T10: what uploading one file answers (the upload pipeline's result). */
export type OfflineUploadResult =
  | { kind: 'clean'; finalKey: string }
  | { kind: 'rejected'; message: string }
  | { kind: 'error'; message: string };

/**
 * B18-T10: uploads a file captured offline to a record's field. By default
 * it is the record screens' upload pipeline (`@attome/xrm/core/entity`'s
 * `UploadPipeline`: resumable parts for a large file, then the virus scan),
 * loaded on the first upload so the offline entry point stays small.
 */
export interface OfflineFileUploader {
  upload(
    target: { entityName: string; recordId: string; fieldName: string },
    file: File,
  ): Promise<OfflineUploadResult>;
}

export const OFFLINE_FILE_UPLOADER = new InjectionToken<OfflineFileUploader>('ATTOME_OFFLINE_FILE_UPLOADER', {
  providedIn: 'root',
  factory: () => {
    const injector = inject(EnvironmentInjector);
    return {
      async upload(target, file) {
        const entity = await import('@attome/xrm/core/entity');
        return new entity.UploadPipeline(injector.get(entity.FileUploadService)).run(target, file);
      },
    };
  },
});

/** A file as the device keeps it: the store seals JSON, so its bytes go as base64. */
interface StoredFile {
  name: string;
  type: string;
  data: string;
}

function readBytes(blob: Blob): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result as ArrayBuffer));
    reader.onerror = () => reject(reader.error);
    reader.readAsArrayBuffer(blob);
  });
}

function toBase64(bytes: Uint8Array): string {
  let text = '';
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    text += String.fromCharCode(...bytes.subarray(i, i + step));
  }
  return btoa(text);
}

function fromBase64(data: string): Uint8Array<ArrayBuffer> {
  const text = atob(data);
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) bytes[i] = text.charCodeAt(i);
  return bytes;
}

const NEXT_SEQ = 'queue-next-seq';

/** A queue key that sorts as text in sequence order. */
function seqKey(seq: number): string {
  return String(seq).padStart(12, '0');
}

/**
 * B18-T6: the changes made offline, in the order they were made. Each gets
 * its sequence number and its `client_op_id` (UUIDv7) once, when queued, so a
 * retried push sends the same ids and the server applies each once (B18-T7).
 * A record created offline gets its UUIDv7 here too, so later changes to it
 * name it before it reaches the server.
 */
@Injectable({ providedIn: 'root' })
export class OfflineQueueService {
  private readonly store = inject(OFFLINE_STORE);

  /** B18-T10: how many changes wait to sync (kept current by this service). */
  readonly waiting = signal(0);

  /** A new record's id, chosen on the device. */
  newRecordId(): string {
    return uuidv7();
  }

  async enqueue(op: NewOp): Promise<QueuedOp> {
    const seq = ((await this.store.get<number>('meta', NEXT_SEQ)) ?? 0) + 1;
    await this.store.put('meta', NEXT_SEQ, seq);
    const queued: QueuedOp = { ...op, seq, client_op_id: uuidv7() };
    await this.store.put('queue', seqKey(seq), queued);
    await this.recount();
    return queued;
  }

  /** Everything waiting, oldest first. */
  async pending(): Promise<QueuedOp[]> {
    const keys = (await this.store.keys('queue')).sort();
    const ops: QueuedOp[] = [];
    for (const k of keys) {
      const op = await this.store.get<QueuedOp>('queue', k);
      if (op) ops.push(op);
    }
    return ops;
  }

  async remove(seq: number): Promise<void> {
    await this.store.delete('queue', seqKey(seq));
    await this.recount();
  }

  /** B18-T10: reads the waiting count again (after a reload, or a wipe). */
  async recount(): Promise<void> {
    this.waiting.set(await this.size());
  }

  /** B18-T10: rewrites a queued change in place (its sequence is kept). */
  async update(op: QueuedOp): Promise<void> {
    await this.store.put('queue', seqKey(op.seq), op);
  }

  /** B18-T10: keeps a file captured offline on the device; its key. */
  async storeFile(file: Blob, name: string): Promise<string> {
    const key = uuidv7();
    const stored: StoredFile = {
      name, type: file.type || 'application/octet-stream', data: toBase64(await readBytes(file)),
    };
    await this.store.put('files', key, stored);
    return key;
  }

  /** B18-T10: a kept file, or null once it was uploaded. */
  async file(key: string): Promise<File | null> {
    const stored = await this.store.get<StoredFile>('files', key);
    if (!stored) return null;
    return new File([fromBase64(stored.data)], stored.name, { type: stored.type });
  }

  async removeFile(key: string): Promise<void> {
    await this.store.delete('files', key);
  }

  /**
   * B18-T10: queues a change with files captured offline (photos,
   * signatures, voice notes) for its fields. A record made offline does not
   * exist on the server until its create is pushed, so its files go on an
   * update queued right after the create.
   */
  async enqueueWithFiles(op: NewOp, files: Record<string, File>): Promise<QueuedOp[]> {
    const keys: Record<string, string> = {};
    for (const [field, file] of Object.entries(files)) {
      keys[field] = await this.storeFile(file, file.name || field);
    }
    if (op.kind === 'create') {
      const created = await this.enqueue(op);
      const withFiles = await this.enqueue({ kind: 'update', entity: op.entity, id: op.id, changed: {}, files: keys });
      return [created, withFiles];
    }
    return [await this.enqueue({ ...op, files: keys })];
  }

  async size(): Promise<number> {
    return (await this.store.keys('queue')).length;
  }
}
