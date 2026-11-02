import { Injectable, inject } from '@angular/core';
import { SdkService, type Page } from '@attome/base';
import { Observable } from 'rxjs';

/** `attome_ai::work_share_routes::ShareDay`. */
export interface ShareDay {
  day: string;
  done_by_agent: number;
  done_by_person: number;
  handed_between: number;
}

/** `attome_ai::work_share_routes::ProcessShare`. */
export interface ProcessShare {
  process_key: string;
  label: string | null;
  label_ar: string | null;
  done_by_agent: number;
  done_by_person: number;
  handed_between: number;
  /** Agents' share of completions, 0..1; null while nothing was done. */
  share: number | null;
  days: ShareDay[];
}

/** `attome_ai::work_share_routes::ShareEvent`. */
export interface ShareEvent {
  id: string;
  entity: string;
  record_id: string;
  at: string;
  agent_session_id: string | null;
}

/** `attome_types::CursorPage<ShareEvent>`. */
export interface ShareEventsPage {
  items: ShareEvent[];
  next_cursor?: string | null;
}

export type DoneBy = 'agent' | 'person';

/** AK3-T6: the work-share routes (administrators). */
@Injectable({ providedIn: 'root' })
export class AiWorkShareService {
  private readonly sdk = inject(SdkService);

  summary(from: string, to: string): Observable<Page<ProcessShare>> {
    return this.sdk.get<Page<ProcessShare>>('/api/v1/admin/ai/work-share', { query: { from, to } });
  }

  events(processKey: string, day: string, by: DoneBy, cursor?: string | null): Observable<ShareEventsPage> {
    const params: Record<string, string> = { day, by };
    if (cursor) params['cursor'] = cursor;
    return this.sdk.get<ShareEventsPage>(
      `/api/v1/admin/ai/work-share/${encodeURIComponent(processKey)}/events`,
      { query: params },
    );
  }
}
