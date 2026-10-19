import { Injectable, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { ApiService } from '@attome/base';
import { OFFLINE_STORE, OfflineQueueService, QueuedOp } from './offline-queue.service';
import { OfflineProfileBundle, PROFILE_KEY } from './state-machine';

/** Most operations one push sends (the server's limit). */
export const PUSH_BATCH = 100;
const FIRST_BACKOFF_MS = 2_000;
const MAX_BACKOFF_MS = 5 * 60_000;
const PERIOD_MS = 5 * 60_000;
const DAY_MS = 86_400_000;

/** One push result (`OpResult`). */
export interface PushResult {
  client_op_id: string;
  status: 'applied' | 'merged' | 'conflict' | 'rejected';
  id: string;
  row_version?: number;
  server_values?: Record<string, unknown>;
  code?: string;
  message?: string;
  link?: string;
}

interface PullAnswer {
  upserts: { entity: string; record: Record<string, unknown> & { id?: string } }[];
  removals: { entity: string; id: string }[];
  done: boolean;
}

/** An operation as the server takes it: everything but the local sequence. */
function withoutSeq(op: QueuedOp): Omit<QueuedOp, 'seq'> {
  const { seq, ...rest } = op;
  void seq;
  return rest;
}

/** The next wait after a failure: doubling from 2 s, at most 5 minutes. Pure. */
export function nextBackoff(previous: number): number {
  return previous <= 0 ? FIRST_BACKOFF_MS : Math.min(previous * 2, MAX_BACKOFF_MS);
}

/** Whether a device last synced too long ago to keep its data. Pure. */
export function expired(lastSyncAt: number | null, maxDaysOffline: number | null, now: number): boolean {
  return lastSyncAt !== null && maxDaysOffline !== null && maxDaysOffline > 0
    && now - lastSyncAt > maxDaysOffline * DAY_MS;
}

/**
 * B18-T6: keeps the device and the server in step. When the device comes
 * online, when the app returns to the foreground, and every five minutes, it
 * pushes the queue in order (in batches of 100), then pulls until the server
 * says it is done. A network failure waits and tries again — 2 s, doubling to
 * 5 minutes — with the same operations and ids; nothing is ever reordered. A
 * device that has not synced within its profile's `max_days_offline` wipes
 * everything it holds. After the pull it refreshes the offline profile
 * (B18-T13: the state models a device follows offline, and that limit),
 * keeping it only when its `bundle_version` changed.
 */
@Injectable({ providedIn: 'root' })
export class SyncService {
  private readonly api = inject(ApiService);
  private readonly store = inject(OFFLINE_STORE);
  private readonly queue = inject(OfflineQueueService);

  readonly syncing = signal(false);
  /** Changes the server refused or that clashed, for the person to see. */
  readonly problems = signal<PushResult[]>([]);
  readonly lastError = signal<string | null>(null);

  private deviceId: string | null = null;
  private backoff = 0;
  private retryTimer: ReturnType<typeof setTimeout> | null = null;
  private periodTimer: ReturnType<typeof setInterval> | null = null;
  private readonly onOnline = () => void this.sync();
  private readonly onVisible = () => {
    if (globalThis.document?.visibilityState === 'visible') void this.sync();
  };

  /** The registered device this store belongs to. */
  setDevice(deviceId: string): void {
    this.deviceId = deviceId;
  }

  /** Starts syncing for the registered device. */
  start(deviceId: string): void {
    this.setDevice(deviceId);
    globalThis.addEventListener?.('online', this.onOnline);
    globalThis.document?.addEventListener('visibilitychange', this.onVisible);
    this.periodTimer = setInterval(() => void this.sync(), PERIOD_MS);
    void this.sync();
  }

  stop(): void {
    globalThis.removeEventListener?.('online', this.onOnline);
    globalThis.document?.removeEventListener('visibilitychange', this.onVisible);
    if (this.periodTimer) clearInterval(this.periodTimer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
    this.periodTimer = null;
    this.retryTimer = null;
  }

  /** One sync; true when it reached the end. */
  async sync(now: number = Date.now()): Promise<boolean> {
    if (!this.deviceId || this.syncing()) return false;
    this.syncing.set(true);
    try {
      const last = await this.store.get<number>('meta', 'lastSyncAt');
      const maxDays = await this.store.get<number>('meta', 'maxDaysOffline');
      if (expired(last, maxDays, now)) {
        await this.store.wipe();
        this.lastError.set('expired');
        return false;
      }
      await this.pushAll();
      await this.pullAll();
      await this.refreshProfile();
      await this.store.put('meta', 'lastSyncAt', now);
      this.backoff = 0;
      this.lastError.set(null);
      return true;
    } catch (e) {
      // Kept as queued, same ids; tried again later.
      this.lastError.set(String((e as { message?: string })?.message ?? e));
      this.backoff = nextBackoff(this.backoff);
      if (this.retryTimer) clearTimeout(this.retryTimer);
      this.retryTimer = setTimeout(() => void this.sync(), this.backoff);
      return false;
    } finally {
      this.syncing.set(false);
    }
  }

  private async pushAll(): Promise<void> {
    for (;;) {
      const batch = (await this.queue.pending()).slice(0, PUSH_BATCH);
      if (!batch.length) return;
      const answer = await firstValueFrom(this.api.post<{ results: PushResult[] }>('/api/v1/offline/push', {
        device_id: this.deviceId,
        ops: batch.map(withoutSeq),
        queue_size: await this.queue.size(),
      }));
      const bySeq = new Map(batch.map(op => [op.client_op_id, op.seq]));
      for (const result of answer.results) {
        const seq = bySeq.get(result.client_op_id);
        if (seq === undefined) continue;
        if (result.status === 'conflict' || result.status === 'rejected') {
          this.problems.update(p => [...p, result]);
        }
        await this.queue.remove(seq);
      }
    }
  }

  /** The offline profile, kept when it changed; none (404) or a failure keeps the last one. */
  private async refreshProfile(): Promise<void> {
    let profile: OfflineProfileBundle;
    try {
      profile = await firstValueFrom(this.api.get<OfflineProfileBundle>('/api/v1/offline/profile'));
    } catch {
      return;
    }
    const kept = await this.store.get<OfflineProfileBundle>('meta', PROFILE_KEY);
    if (kept?.bundle_version === profile.bundle_version) return;
    await this.store.put('meta', PROFILE_KEY, profile);
    await this.store.put('meta', 'maxDaysOffline', profile.max_days_offline ?? null);
  }

  private async pullAll(): Promise<void> {
    for (let page = 0; page < 1000; page++) {
      const answer = await firstValueFrom(
        this.api.post<PullAnswer>('/api/v1/offline/pull', { device_id: this.deviceId }),
      );
      for (const u of answer.upserts) {
        if (u.record?.id) await this.store.putRecord(u.entity, String(u.record.id), u.record);
      }
      for (const r of answer.removals) await this.store.deleteRecord(r.entity, r.id);
      if (answer.done) return;
    }
  }
}
