import { Injectable, inject } from '@angular/core';
import { ApiService } from '@attome/base';
import { Observable } from 'rxjs';

/** A hand-off to sales (E9-T5). */
export interface Handoff {
  id: string;
  program_id: string;
  person_id: string;
  status: 'pending' | 'accepted' | 'returned' | 'overdue' | string;
  score?: number | null;
  summary?: { score?: number; threshold?: number; content_seen?: { kind: string; id: string }[]; next_step?: string } | null;
  assigned_to?: string | null;
  due_at?: string | null;
  decided_at?: string | null;
  return_reason?: string | null;
  created_at: string;
}

/** A person's place in one nurture programme. */
export interface NurtureState {
  program_id: string;
  track_id?: string | null;
  status: string;
  position: number;
  next_due_at?: string | null;
  paused_reason?: string | null;
}

export interface ContentSeen {
  content_kind: string;
  content_id: string;
  first_seen_at: string;
}

/** `GET /api/v1/marketing/people/{person_id}/nurture-history` (E9-T8). */
export interface NurtureHistory {
  person_id: string;
  states: NurtureState[];
  content_seen: ContentSeen[];
  handoffs: Handoff[];
}

/** The hand-off and nurture routes (E9-T8). */
@Injectable({ providedIn: 'root' })
export class NurtureService {
  private readonly api = inject(ApiService);

  history(person: string, entity: string): Observable<NurtureHistory> {
    return this.api.get<NurtureHistory>(
      `/api/v1/marketing/people/${encodeURIComponent(person)}/nurture-history`, { entity });
  }

  accept(handoff: string): Observable<Handoff> {
    return this.api.post<Handoff>(`/api/v1/marketing/handoffs/${encodeURIComponent(handoff)}/accept`, {});
  }

  /** Gives the person back; `wakeUpOn` (an ISO date-time) is when nurture starts again. */
  returnHandoff(handoff: string, reason: string, wakeUpOn: string | null): Observable<{ handoff_id: string; recycled: boolean }> {
    return this.api.post<{ handoff_id: string; recycled: boolean }>(
      `/api/v1/marketing/handoffs/${encodeURIComponent(handoff)}/return`,
      { reason, wake_up_on: wakeUpOn });
  }
}
