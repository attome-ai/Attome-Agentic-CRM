import { Injectable, inject } from '@angular/core';
import { Subject } from 'rxjs';

import { ATTOME_CONFIG } from './config';

/** One record change the live channel reports. */
export interface LiveRecordChange {
  entity: string;
  id: string;
  /** `create`, `update`, `delete` or `restore`. */
  op: string;
}

/** A `records` frame: the changes, or `overflow` when there were too many to list. */
export type LiveRecords = { changes: LiveRecordChange[] } | { overflow: true };

/**
 * The one live connection a signed-in app keeps (`GET /api/v1/live`,
 * Server-Sent Events). It carries the published model's version (Y14-T3) and,
 * for the entities a page watches, their record changes (A13-T4). Watching
 * or unwatching an entity reopens the connection with the new set; the
 * browser reconnects by itself after a drop. Where `EventSource` does not
 * exist (tests, server rendering) nothing opens.
 */
@Injectable({ providedIn: 'root' })
export class LiveChannel {
  private readonly config = inject(ATTOME_CONFIG, { optional: true });
  private source: EventSource | null = null;
  private wanted = false;
  private readonly watched = new Map<string, number>();

  /** The data of every `hello` and `model-version` frame. */
  readonly modelFrames = new Subject<string>();
  /** The record changes of the watched entities. */
  readonly records = new Subject<LiveRecords>();
  /** J11-T1: the signed-in person's inbox changed; the number is its unread count. */
  readonly notifications = new Subject<number>();

  /** Opens the channel (once). */
  connect(): void {
    if (this.wanted) return;
    this.wanted = true;
    this.open();
  }

  /** Closes the channel. */
  disconnect(): void {
    this.wanted = false;
    this.source?.close();
    this.source = null;
  }

  /** Sends this entity's record changes while the returned function is not called. */
  watch(entity: string): () => void {
    const count = this.watched.get(entity) ?? 0;
    this.watched.set(entity, count + 1);
    this.wanted = true;
    if (count === 0) this.open();
    let done = false;
    return () => {
      if (done) return;
      done = true;
      const left = (this.watched.get(entity) ?? 1) - 1;
      if (left > 0) {
        this.watched.set(entity, left);
      } else {
        this.watched.delete(entity);
        this.open();
      }
    };
  }

  /** The entities watched now, sorted. */
  watching(): string[] {
    return [...this.watched.keys()].sort();
  }

  /** Applies one `records` frame's data. */
  receiveRecords(data: string): void {
    try {
      const parsed = JSON.parse(data) as { changes?: unknown; overflow?: unknown };
      if (parsed.overflow === true) {
        this.records.next({ overflow: true });
      } else if (Array.isArray(parsed.changes)) {
        this.records.next({ changes: parsed.changes as LiveRecordChange[] });
      }
    } catch {
      // A malformed frame is dropped; the next one carries newer changes.
    }
  }

  /** Applies one `notifications` frame's data. */
  receiveNotifications(data: string): void {
    try {
      const parsed = JSON.parse(data) as { unread?: unknown };
      if (typeof parsed.unread === 'number') this.notifications.next(parsed.unread);
    } catch {
      // A malformed frame is dropped; the bell's own poll still runs.
    }
  }

  private open(): void {
    if (!this.wanted || typeof EventSource === 'undefined') return;
    this.source?.close();
    const entities = this.watching();
    const query = entities.length ? `?entities=${encodeURIComponent(entities.join(','))}` : '';
    const source = new EventSource(`${this.config?.apiUrl ?? ''}/api/v1/live${query}`, { withCredentials: true });
    const model = (event: Event) => this.modelFrames.next((event as MessageEvent<string>).data);
    source.addEventListener('hello', model);
    source.addEventListener('model-version', model);
    source.addEventListener('records', event => this.receiveRecords((event as MessageEvent<string>).data));
    source.addEventListener('notifications', event =>
      this.receiveNotifications((event as MessageEvent<string>).data));
    this.source = source;
  }
}
