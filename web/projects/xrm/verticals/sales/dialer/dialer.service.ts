import { Injectable, inject } from '@angular/core';
import { ApiComponents, ApiService } from '@attome/base';
import { Observable } from 'rxjs';

type S = ApiComponents['schemas'];
export type ClaimResult = S['ClaimResult'];
export type ClaimedMember = S['ClaimedMember'];
export type CallOutcomeBody = S['SalesCallOutcomeBody'];
export type CallOutcomeSaved = S['SalesCallOutcomeSaved'];
export type CallSkipped = S['SalesCallSkipped'];
export type CallHandle = S['CallHandle'];
export type DialRequest = S['DialRequest'];

/** D21's dialer routes, typed from the generated API types. */
@Injectable({ providedIn: 'root' })
export class DialerService {
  private readonly api = inject(ApiService);

  /** Takes the next callable member of the list (null when none is left). */
  claim(list: string): Observable<ClaimResult> {
    return this.api.post<ClaimResult>(`/api/v1/sales/call-lists/${encodeURIComponent(list)}/claim`, {});
  }

  /** Rings the agent's phone, then the member. */
  dial(list: string, body: DialRequest): Observable<CallHandle> {
    return this.api.post<CallHandle>(`/api/v1/sales/call-lists/${encodeURIComponent(list)}/dial`, body);
  }

  /** Drops the recorded message into the call (the list must allow it). */
  voicemail(list: string, callId: string, recordingUrl: string): Observable<unknown> {
    return this.api.post<unknown>(`/api/v1/sales/call-lists/${encodeURIComponent(list)}/voicemail`, {
      call_id: callId,
      recording_url: recordingUrl,
    });
  }

  /** Saves the call's outcome. */
  outcome(member: string, body: CallOutcomeBody): Observable<CallOutcomeSaved> {
    return this.api.post<CallOutcomeSaved>(
      `/api/v1/sales/call-list-members/${encodeURIComponent(member)}/outcome`, body);
  }

  /** Passes over the member with a reason. */
  skip(member: string, reason: string): Observable<CallSkipped> {
    return this.api.post<CallSkipped>(
      `/api/v1/sales/call-list-members/${encodeURIComponent(member)}/skip`, { reason });
  }
}
