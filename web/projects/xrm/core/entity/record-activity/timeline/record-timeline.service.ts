import { inject, Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
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

/** B1-T3: one event a timeline summary cites. */
export interface TimelineCitation {
  evidence: string;
  kind: TimelineEntryKind;
  source_id: string;
  occurred_at: string;
}

/** B1-T3: the timeline's AI summary, citing its events. */
export interface TimelineSummary {
  answer: string;
  citations: TimelineCitation[];
}

interface SummaryOutcome {
  status: string;
  result?: { answer?: string | null; citations?: TimelineCitation[] };
}

/** The summary in an action outcome, when it completed with an answer. Pure. */
export function timelineSummary(outcome: SummaryOutcome | null | undefined): TimelineSummary | null {
  if (!outcome || outcome.status !== 'completed') return null;
  const answer = outcome.result?.answer;
  if (typeof answer !== 'string' || !answer.trim()) return null;
  return { answer, citations: outcome.result?.citations ?? [] };
}

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

  /**
   * B1-T3: the AI summary of the record's timeline (`timeline.summarize`),
   * from the events the person may see; `null` when there is none.
   */
  summary(entityName: string, recordId: string): Observable<TimelineSummary | null> {
    return this.api
      .post<SummaryOutcome>('/api/v1/actions/timeline.summarize/invoke', {
        args: { entity: entityName, record_id: recordId },
      })
      .pipe(map(timelineSummary));
  }

  history(entityName: string, recordId: string, cursor?: string | null): Observable<RecordHistoryPage> {
    const params: Record<string, string> = {};
    if (cursor) params['cursor'] = cursor;
    return this.api.get<RecordHistoryPage>(
      `/api/v1/${encodeURIComponent(entityName)}/${encodeURIComponent(recordId)}/history`, params,
    );
  }
}
