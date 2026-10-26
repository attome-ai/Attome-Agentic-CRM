// @attome/xrm/offline — the device's offline data (B18-T6): an encrypted
// store, the ordered queue of changes made offline, and the sync loop;
// B18-T13: state models followed offline; B18-T9: conflicts and failures.
export { IndexedDbBackend, MemoryBackend, OfflineStore, uuidv7 } from './offline-store';
export type { KvBackend, StoreName } from './offline-store';
export { OFFLINE_FILE_UPLOADER, OFFLINE_STORE, OfflineQueueService } from './offline-queue.service';
export type { OfflineFileUploader, OfflineUploadResult } from './offline-queue.service';
// B18-T10: online state, the waiting changes and Sync now, for the header.
export { SyncStatusComponent } from './sync-status.component';
// B18-T8 — entity reads and writes served on the device while offline.
export {
  answerOffline, keepSchema, offlineDataInterceptor, offlineRoute, ruleErrors, schemaKey,
} from './offline-data.interceptor';
export type { NewOp, QueuedOp } from './offline-queue.service';
export { PUSH_BATCH, SyncService, expired, nextBackoff } from './sync.service';
// B18-T11: search over the device's records, Arabic normalised.
export { OfflineSearch, normaliseArabic, recordText } from './offline-search';
export type { OfflineHit } from './offline-search';
export type { PushResult, SyncProblem } from './sync.service';
export { ConflictDialogComponent, conflictRows, resolvedOp } from './conflict-dialog.component';
export type { ConflictRow } from './conflict-dialog.component';
export { SyncErrorsPanelComponent, errorLink } from './sync-errors-panel.component';
export {
  PROFILE_KEY, availableTransitions, currentState, queueTransition, storedStateModel, transitionOp,
} from './state-machine';
export type { GuardEvaluator, OfflineProfileBundle, OfflineStateModel, OfflineTransition } from './state-machine';
