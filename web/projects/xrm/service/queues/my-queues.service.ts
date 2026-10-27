import { Injectable, inject } from '@angular/core';
import { ApiService } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityService } from '@attome/xrm/core/entity';
import { Observable, concat, forkJoin, map, of, catchError, toArray } from 'rxjs';

/** A V7 queue (`queue`). */
export interface QueueRef {
  id: string;
  name: string;
}

/** A V7 queue item (`queue_item`) not yet done. */
export interface QueueItemRow {
  id: string;
  queue_ref: string;
  record_entity: string;
  record_id: string;
  priority: string;
  status: 'waiting' | 'picked' | string;
  assigned_ref: string | null;
  entered_at: string;
}

/** `attome_project::queue::QueueItemState`. */
export interface QueueItemState {
  id: string;
  queue_id: string;
  status: string;
  assigned_ref: string | null;
}

/** One queue and its open items, for the combined list. */
export interface QueueGroup {
  queue: QueueRef;
  items: QueueItemRow[];
}

export type StarterSetKey = 'it' | 'care' | 'hr';

/** A starter queue, named in both languages. */
export interface StarterQueue {
  en: string;
  ar: string;
}

/** G4-T3: the queues each starter set creates. */
export const STARTER_SETS: Readonly<Record<StarterSetKey, readonly StarterQueue[]>> = {
  it: [
    { en: 'Service Desk', ar: 'مكتب الخدمة' },
    { en: 'Access Requests', ar: 'طلبات الصلاحيات' },
    { en: 'Network and Infrastructure', ar: 'الشبكات والبنية التحتية' },
    { en: 'Hardware', ar: 'الأجهزة' },
  ],
  care: [
    { en: 'General Enquiries', ar: 'الاستفسارات العامة' },
    { en: 'Billing', ar: 'الفوترة' },
    { en: 'Complaints', ar: 'الشكاوى' },
    { en: 'Returns', ar: 'المرتجعات' },
  ],
  hr: [
    { en: 'Onboarding', ar: 'التهيئة' },
    { en: 'Payroll', ar: 'الرواتب' },
    { en: 'Leave', ar: 'الإجازات' },
    { en: 'Employee Relations', ar: 'علاقات الموظفين' },
  ],
};

const PRIORITY_RANK: Readonly<Record<string, number>> = { critical: 0, high: 1, medium: 2, low: 3 };

/** Items grouped by queue, queues by name, items by priority then age; a
 *  queue with no open item is left out. Pure. */
export function groupByQueue(queues: readonly QueueRef[], items: readonly QueueItemRow[]): QueueGroup[] {
  return [...queues]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(queue => ({
      queue,
      items: items
        .filter(i => i.queue_ref === queue.id)
        .sort((a, b) =>
          (PRIORITY_RANK[a.priority] ?? 4) - (PRIORITY_RANK[b.priority] ?? 4)
          || a.entered_at.localeCompare(b.entered_at)),
    }))
    .filter(g => g.items.length > 0);
}

/** The starter queues `key` adds that are not there yet (by either name). Pure. */
export function missingStarters(key: StarterSetKey, queues: readonly QueueRef[]): StarterQueue[] {
  const have = new Set(queues.map(q => q.name.trim().toLowerCase()));
  return STARTER_SETS[key].filter(s => !have.has(s.en.toLowerCase()) && !have.has(s.ar));
}

function text(record: EntityRecord, field: string): string {
  const v = (record.data as Record<string, unknown>)[field];
  return v === null || v === undefined ? '' : String(v);
}

/** What one bulk action did. */
export interface BulkOutcome {
  done: number;
  failed: number;
}

/** G4-T3: the V7 queue items behind "my queues", and their moves (G4-T2). */
@Injectable({ providedIn: 'root' })
export class MyQueuesService {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);

  queues(): Observable<QueueRef[]> {
    return this.entities.list('queue', { limit: 200, sorts: [{ field: 'name', dir: 'asc' }] }).pipe(
      map(page => page.data.map(r => ({ id: r.id, name: text(r, 'name') || r.id }))),
    );
  }

  openItems(): Observable<QueueItemRow[]> {
    return this.entities.list('queue_item', {
      filters: [{ field: 'status', op: 'ne', value: 'done' }],
      sorts: [{ field: 'entered_at', dir: 'asc' }],
      limit: 200,
    }).pipe(
      map(page => page.data.map(r => ({
        id: r.id,
        queue_ref: text(r, 'queue_ref'),
        record_entity: text(r, 'record_entity'),
        record_id: text(r, 'record_id'),
        priority: text(r, 'priority') || 'medium',
        status: text(r, 'status') || 'waiting',
        assigned_ref: text(r, 'assigned_ref') || null,
        entered_at: text(r, 'entered_at'),
      }))),
    );
  }

  pick(id: string): Observable<QueueItemState> {
    return this.api.post<QueueItemState>(`/api/v1/queue-items/${encodeURIComponent(id)}/pick`, {});
  }

  release(id: string): Observable<QueueItemState> {
    return this.api.post<QueueItemState>(`/api/v1/queue-items/${encodeURIComponent(id)}/release`, {});
  }

  transfer(id: string, queueId: string): Observable<QueueItemState> {
    return this.api.post<QueueItemState>(
      `/api/v1/queue-items/${encodeURIComponent(id)}/transfer`,
      { queue_id: queueId },
    );
  }

  /** Runs `act` on each id one after another; a refusal counts as failed. */
  bulk(ids: readonly string[], act: (id: string) => Observable<unknown>): Observable<BulkOutcome> {
    if (!ids.length) return of({ done: 0, failed: 0 });
    return concat(...ids.map(id => act(id).pipe(map(() => true), catchError(() => of(false))))).pipe(
      toArray(),
      map(results => ({ done: results.filter(Boolean).length, failed: results.filter(r => !r).length })),
    );
  }

  /** Creates the starter queues not there yet, named in `lang`. */
  createStarters(starters: readonly StarterQueue[], lang: string): Observable<number> {
    if (!starters.length) return of(0);
    return forkJoin(starters.map(s => this.entities.create('queue', { name: lang === 'ar' ? s.ar : s.en }))).pipe(
      map(created => created.length),
    );
  }
}
