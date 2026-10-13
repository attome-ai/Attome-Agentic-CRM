import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents } from '@attome/base';

type Schemas = ApiComponents['schemas'];

/** `POST /api/v1/ticket/{id}/apply-sla-policy` (200). */
export type ApplySlaPolicyResponse = Schemas['ApplySlaPolicyResponse'];
/** The ticket's SLA clock after a pause/resume. */
export type SlaClockView = Schemas['ClockView'];
/** `POST /api/v1/ticket/{id}/sla/recalculate`. */
export type SlaRecalculation = Schemas['SlaRecalculation'];
export type SlaPauseReason = Schemas['PauseReason'];
export type SlaUnresolvedReason = Schemas['UnresolvedReason'];

/** Every pause reason the backend accepts, in display order. */
export const SLA_PAUSE_REASONS: readonly SlaPauseReason[] = ['waiting_customer', 'on_hold', 'out_of_scope'];

/**
 * The ticket SLA routes (`attome-service`'s `sla.rs` and `clock.rs`). Every one
 * requires `service_ticket.update`; a caller without it gets a 403, which
 * the caller surfaces rather than hiding the controls on a guess.
 */
@Injectable({ providedIn: 'root' })
export class SlaService {
  private readonly api = inject(ApiService);

  /**
   * Picks the matching policy (severity for an incident, then priority, then
   * the fallback) and calculates `resolution_due_at` from now. `null` is the
   * route's 204: no matching or fallback policy is configured.
   */
  applyPolicy(ticketId: string): Observable<ApplySlaPolicyResponse | null> {
    return this.api.post<ApplySlaPolicyResponse | null>(`/api/v1/ticket/${ticketId}/apply-sla-policy`, {});
  }

  pauseClock(ticketId: string, reason: SlaPauseReason): Observable<SlaClockView> {
    return this.api.post<SlaClockView>(`/api/v1/ticket/${ticketId}/sla-clock/pause`, { reason });
  }

  resumeClock(ticketId: string): Observable<SlaClockView> {
    return this.api.post<SlaClockView>(`/api/v1/ticket/${ticketId}/sla-clock/resume`, {});
  }

  /** Recalculates an unresolved SLA; a no-op (`recalculated: false`) otherwise. */
  recalculate(ticketId: string): Observable<SlaRecalculation> {
    return this.api.post<SlaRecalculation>(`/api/v1/ticket/${ticketId}/sla/recalculate`, {});
  }
}
