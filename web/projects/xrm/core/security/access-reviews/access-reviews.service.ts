import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents } from '@attome/base';

/** One access review campaign (`GET /api/v1/admin/security/access-reviews`). */
export interface AccessReviewCampaign {
  id: string;
  name: string;
  /** `role`, `team` or `entity_share`. */
  scope: string;
  due_date: string;
  status: string;
  item_count: number;
  decided_count: number;
  created_at: string;
}

/** One access to keep or revoke (the generated `AccessReviewItem` schema). */
export type AccessReviewItem = ApiComponents['schemas']['AccessReviewItem'];

export type AccessReviewDecision = 'keep' | 'revoke';

/** Q11-T1 — the access review routes the review screen reads and decides through. */
@Injectable({ providedIn: 'root' })
export class AccessReviewsService {
  private readonly api = inject(ApiService);

  listCampaigns(): Observable<AccessReviewCampaign[]> {
    return this.api.getAllPages<AccessReviewCampaign>('/api/v1/admin/security/access-reviews');
  }

  listItems(campaignId: string): Observable<AccessReviewItem[]> {
    return this.api.getAllPages<AccessReviewItem>(
      `/api/v1/admin/security/access-reviews/${campaignId}/items`,
    );
  }

  decide(
    campaignId: string,
    itemId: string,
    decision: AccessReviewDecision,
    reason: string,
  ): Observable<AccessReviewItem> {
    return this.api.post<AccessReviewItem>(
      `/api/v1/admin/security/access-reviews/${campaignId}/items/${itemId}/decide`,
      { decision, reason: reason.trim() || null },
    );
  }
}

/** One CSV field, quoted when it holds a comma, quote or line break. */
function csvField(value: string | null | undefined): string {
  const text = value ?? '';
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

/** Q11-T1: a campaign's items as CSV evidence, one row per access. */
export function evidenceCsv(campaign: AccessReviewCampaign, items: readonly AccessReviewItem[]): string {
  const header = [
    'campaign', 'campaign_id', 'scope', 'due_date', 'item_id', 'subject_user_id', 'grant_id',
    'reviewer_user_id', 'decision', 'reason', 'decided_by', 'decided_at', 'revoked_at',
  ];
  const rows = items.map(item => [
    campaign.name, campaign.id, campaign.scope, campaign.due_date, item.id, item.subject_user_id,
    item.grant_id, item.reviewer_user_id, item.decision, item.decision_reason, item.decided_by,
    item.decided_at, item.revoked_at,
  ].map(csvField).join(','));
  return [header.join(','), ...rows].join('\r\n') + '\r\n';
}
