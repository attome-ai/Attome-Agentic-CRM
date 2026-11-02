import { inject, Injectable } from '@angular/core';
import { ApiComponents, SdkService } from '@attome/base';
import { map, Observable } from 'rxjs';

export type LeadConvertBody = ApiComponents['schemas']['LeadConvertBody'];
export type LeadConverted = ApiComponents['schemas']['LeadConverted'];
export type LeadConversionUndone = ApiComponents['schemas']['LeadConversionUndone'];
export type DuplicateMatch = ApiComponents['schemas']['DuplicateMatch'];

/** `LeadConvertPreview`, its three value maps typed as the free-form objects they are. */
export interface LeadConvertPreview {
  lead_id: string;
  account: Record<string, unknown>;
  contact: Record<string, unknown>;
  opportunity: Record<string, unknown>;
  account_matches: DuplicateMatch[];
  contact_matches: DuplicateMatch[];
  hidden_matches: number;
}

/** A target's choice: `create`, `link` (to an existing record) or `skip` (not the account). */
export type ConvertMode = 'create' | 'link' | 'skip';

/** The lead's state and version, read before a conversion or a disqualification. */
export interface LeadHead {
  id: string;
  row_version: number;
  name: string;
  status: string | null;
}

/** The reasons a disqualified lead may carry (crm pack 0005's lead lifecycle). */
export const DISQUALIFY_REASONS = [
  'no_budget', 'no_need', 'no_authority', 'bad_timing', 'competitor', 'unreachable', 'duplicate', 'other',
] as const;
export type DisqualifyReason = (typeof DISQUALIFY_REASONS)[number];

/** Each target entity's name field, to show a match by name. */
const NAME_FIELD: Record<string, string> = { account: 'name', contact: 'full_name', lead: 'name' };

function recordData(r: unknown): Record<string, unknown> {
  const data = (r as { data?: unknown } | null)?.data;
  return data !== null && typeof data === 'object' ? (data as Record<string, unknown>) : {};
}

/** D3-T3: the lead conversion routes (D3-T2) and the lead reads around them. */
@Injectable({ providedIn: 'root' })
export class LeadConvertApiService {
  private readonly sdk = inject(SdkService);

  lead(id: string): Observable<LeadHead> {
    return this.sdk.get<{ id: string; row_version: number; data: unknown }>(`/api/v1/lead/${encodeURIComponent(id)}`).pipe(
      map(r => {
        const data = recordData(r);
        return {
          id: r.id,
          row_version: Number(r.row_version ?? 0),
          name: typeof data['name'] === 'string' ? data['name'] : r.id,
          status: typeof data['lead_status'] === 'string' ? data['lead_status'] : null,
        };
      }),
    );
  }

  /** A match's display name; its id when the record has no name. */
  matchName(entity: 'account' | 'contact', id: string): Observable<string> {
    return this.sdk.get<{ data: unknown }>(`/api/v1/${entity}/${encodeURIComponent(id)}`).pipe(
      map(r => {
        const name = recordData(r)[NAME_FIELD[entity]];
        return typeof name === 'string' && name.trim() ? name : id;
      }),
    );
  }

  preview(id: string): Observable<LeadConvertPreview> {
    return this.sdk.get<LeadConvertPreview>(`/api/v1/sales/leads/${encodeURIComponent(id)}/convert`);
  }

  convert(id: string, body: LeadConvertBody, rowVersion: number): Observable<LeadConverted> {
    return this.sdk.post<LeadConverted>(`/api/v1/sales/leads/${encodeURIComponent(id)}/convert`, { body }, {
      ifMatch: rowVersion,
    });
  }

  undo(conversionId: string): Observable<LeadConversionUndone> {
    return this.sdk.post<LeadConversionUndone>(
      `/api/v1/sales/lead-conversions/${encodeURIComponent(conversionId)}/undo`, { body: {} },
    );
  }

  /** Moves the lead to `disqualified` with its reason, in one update (the state model checks the reason). */
  disqualify(id: string, reason: DisqualifyReason, rowVersion: number): Observable<unknown> {
    return this.sdk.patch(
      `/api/v1/lead/${encodeURIComponent(id)}`,
      { body: { lead_status: 'disqualified', disqualify_reason: reason }, ifMatch: rowVersion },
    );
  }
}
