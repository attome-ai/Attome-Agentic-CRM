import { Injectable, InjectionToken, inject } from '@angular/core';
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
}

export type NewOp = Omit<QueuedOp, 'seq' | 'client_op_id'>;

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

  /** A new record's id, chosen on the device. */
  newRecordId(): string {
    return uuidv7();
  }

  async enqueue(op: NewOp): Promise<QueuedOp> {
    const seq = ((await this.store.get<number>('meta', NEXT_SEQ)) ?? 0) + 1;
    await this.store.put('meta', NEXT_SEQ, seq);
    const queued: QueuedOp = { ...op, seq, client_op_id: uuidv7() };
    await this.store.put('queue', seqKey(seq), queued);
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
  }

  async size(): Promise<number> {
    return (await this.store.keys('queue')).length;
  }
}
