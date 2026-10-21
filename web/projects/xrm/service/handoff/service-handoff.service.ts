import { Injectable, inject } from '@angular/core';
import { ApiService, type Page } from '@attome/base';
import { Observable, map, of, shareReplay, catchError } from 'rxjs';

/** `attome_service::handoff::Handoff`. */
export interface ServiceHandoff {
  id: string;
  ticket_id: string;
  from_kind: 'agent' | 'user' | string;
  from_ref: string;
  to_kind: 'agent' | 'user' | 'queue' | string;
  to_ref: string;
  summary: string;
  reasoning: string;
  agent_session_ref: string | null;
  status: 'pending' | 'accepted' | 'returned' | 'cancelled' | string;
  created_at: string;
  accepted_at: string | null;
  returned_at: string | null;
  row_version: number;
}

/** The icon of a hand-off party, so agent and human hand-offs are told apart. Pure. */
export function partyIcon(kind: string): string {
  switch (kind) {
    case 'agent': return 'las la-robot';
    case 'queue': return 'las la-users';
    default: return 'las la-user';
  }
}

/** Whether a hand-off can be handed back: one an agent made, still open. Pure. */
export function canHandBack(handoff: ServiceHandoff): boolean {
  return handoff.from_kind === 'agent' && (handoff.status === 'pending' || handoff.status === 'accepted');
}

/** AI7-T6: the hand-off routes (AI7-T5). */
@Injectable({ providedIn: 'root' })
export class ServiceHandoffService {
  private readonly api = inject(ApiService);
  private readonly names = new Map<string, Observable<string>>();

  pending(): Observable<Page<ServiceHandoff>> {
    return this.api.get<Page<ServiceHandoff>>('/api/v1/service/handoffs?page=1&page_size=100');
  }

  forTicket(ticketId: string): Observable<Page<ServiceHandoff>> {
    return this.api.get<Page<ServiceHandoff>>(
      `/api/v1/service/tickets/${encodeURIComponent(ticketId)}/handoffs?page=1&page_size=20`,
    );
  }

  accept(handoff: ServiceHandoff): Observable<ServiceHandoff> {
    return this.api.post<ServiceHandoff>(
      `/api/v1/service/handoffs/${encodeURIComponent(handoff.id)}/accept`,
      {},
      { ifMatch: handoff.row_version },
    );
  }

  handBack(handoff: ServiceHandoff, note: string): Observable<ServiceHandoff> {
    return this.api.post<ServiceHandoff>(
      `/api/v1/service/handoffs/${encodeURIComponent(handoff.id)}/return`,
      { note },
      { ifMatch: handoff.row_version },
    );
  }

  /** A person's name (their user name, else email), cached; their id when unreadable. */
  personName(userId: string): Observable<string> {
    let name = this.names.get(userId);
    if (!name) {
      name = this.api.get<{ data: Record<string, unknown> }>(`/api/v1/user_account/${encodeURIComponent(userId)}`).pipe(
        map(r => {
          const d = r?.data ?? {};
          const text = (k: string) => (typeof d[k] === 'string' && (d[k] as string).trim() ? (d[k] as string) : null);
          return text('user_name') ?? text('email') ?? userId;
        }),
        catchError(() => of(userId)),
        shareReplay(1),
      );
      this.names.set(userId, name);
    }
    return name;
  }
}
