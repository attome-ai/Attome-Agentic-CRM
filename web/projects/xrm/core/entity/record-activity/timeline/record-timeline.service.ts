import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiComponents, ApiService } from '@attome/base';

/**
 * U3/U6 (basic-units plan, D-601) — the record timeline and record history
 * routes, `crates/engine/attome-records/src/entity_crud/{timeline,history}.rs`.
 * Both are keyset-paged: pass the previous page's `next_cursor` back to get
 * the next page; a missing `next_cursor` means there is none.
 */
export type TimelineEntry       = ApiComponents['schemas']['TimelineEntry'];
export type TimelineEntryKind   = ApiComponents['schemas']['TimelineEntryKind'];
export type TimelinePage        = ApiComponents['schemas']['CursorPage_TimelineEntry'];
export type RecordHistoryChange = ApiComponents['schemas']['RecordHistoryChange'];
export type RecordHistoryField  = ApiComponents['schemas']['RecordHistoryField'];
export type RecordHistoryPage   = ApiComponents['schemas']['CursorPage_RecordHistoryChange'];

/** Every timeline kind, in the order the filter chips show them. */
export const TIMELINE_KINDS: readonly TimelineEntryKind[] = [
  'audit_event', 'state_transition', 'communication', 'note', 'activity', 'decision',
];

export interface TimelineRequest {
  cursor?: string | null;
  pageSize?: number;
  /** Empty or omitted = every kind. */
  kinds?: readonly TimelineEntryKind[];
}

@Injectable({ providedIn: 'root' })
export class RecordTimelineService {
  private readonly api = inject(ApiService);

  timeline(entityName: string, recordId: string, req: TimelineRequest = {}): Observable<TimelinePage> {
    const params: Record<string, string> = {};
    if (req.cursor) params['cursor'] = req.cursor;
    if (req.pageSize) params['page_size'] = String(req.pageSize);
    if (req.kinds?.length) params['kinds'] = req.kinds.join(',');
    return this.api.get<TimelinePage>(
      `/api/v1/${encodeURIComponent(entityName)}/${encodeURIComponent(recordId)}/timeline`, params,
    );
  }

  history(entityName: string, recordId: string, cursor?: string | null): Observable<RecordHistoryPage> {
    const params: Record<string, string> = {};
    if (cursor) params['cursor'] = cursor;
    return this.api.get<RecordHistoryPage>(
      `/api/v1/${encodeURIComponent(entityName)}/${encodeURIComponent(recordId)}/history`, params,
    );
  }
}
