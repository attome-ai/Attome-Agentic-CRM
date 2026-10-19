// @attome/xrm/offline — the device's offline data (B18-T6): an encrypted
// store, the ordered queue of changes made offline, and the sync loop.
export { IndexedDbBackend, MemoryBackend, OfflineStore, uuidv7 } from './offline-store';
export type { KvBackend, StoreName } from './offline-store';
export { OFFLINE_STORE, OfflineQueueService } from './offline-queue.service';
export type { NewOp, QueuedOp } from './offline-queue.service';
export { PUSH_BATCH, SyncService, expired, nextBackoff } from './sync.service';
export type { PushResult } from './sync.service';
