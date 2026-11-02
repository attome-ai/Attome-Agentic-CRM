import { Injectable, inject } from '@angular/core';
import { ApiComponents, SdkService } from '@attome/base';
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
  private readonly sdk = inject(SdkService);

  /** Takes the next callable member of the list (null when none is left). */
  claim(list: string): Observable<ClaimResult> {
    return this.sdk.post<ClaimResult>(`/api/v1/sales/call-lists/${encodeURIComponent(list)}/claim`, { body: {} });
  }

  /** Rings the agent's phone, then the member. */
  dial(list: string, body: DialRequest): Observable<CallHandle> {
    return this.sdk.post<CallHandle>(`/api/v1/sales/call-lists/${encodeURIComponent(list)}/dial`, { body: body });
  }

  /** Drops the recorded message into the call (the list must allow it). */
  voicemail(list: string, callId: string, recordingUrl: string): Observable<unknown> {
    return this.sdk.post<unknown>(
      `/api/v1/sales/call-lists/${encodeURIComponent(list)}/voicemail`,
      { body: {
      call_id: callId,
      recording_url: recordingUrl,
    } },
    );
  }

  /** Saves the call's outcome. */
  outcome(member: string, body: CallOutcomeBody): Observable<CallOutcomeSaved> {
    return this.sdk.post<CallOutcomeSaved>(
      `/api/v1/sales/call-list-members/${encodeURIComponent(member)}/outcome`,
      { body: body },
    );
  }

  /** Passes over the member with a reason. */
  skip(member: string, reason: string): Observable<CallSkipped> {
    return this.sdk.post<CallSkipped>(
      `/api/v1/sales/call-list-members/${encodeURIComponent(member)}/skip`,
      { body: { reason } },
    );
  }
}
