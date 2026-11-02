import { Injectable, inject } from '@angular/core';
import { ApiComponents, ApiService } from '@attome/base';
import { Observable, map } from 'rxjs';

export type MarketingListCount = ApiComponents['schemas']['MarketingListCount'];
export type MarketingListSample = ApiComponents['schemas']['MarketingListSample'];
export type MarketingListExplanation = ApiComponents['schemas']['MarketingListExplanation'];

/**
 * One use of a list (`GET /api/v1/marketing/lists/{id}/usage`, E7-T9): an
 * email or SMS send, a nurture programme or a journey.
 */
export interface MarketingListUse {
  kind: 'email_send' | 'sms_send' | 'nurture_program' | 'journey' | string;
  id: string;
  name?: string | null;
  status?: string | null;
}

/** The list routes the segment tab reads, each computed as the caller. */
@Injectable({ providedIn: 'root' })
export class SegmentInsightService {
  private readonly api = inject(ApiService);

  private base(list: string): string {
    return `/api/v1/marketing/lists/${encodeURIComponent(list)}`;
  }

  /** The list's size, estimated unless `exact`; with a purpose, also how many can be reached. */
  count(list: string, options: { exact?: boolean; purpose?: string } = {}): Observable<MarketingListCount> {
    const params: Record<string, string> = {};
    if (options.exact) params['exact'] = 'true';
    if (options.purpose) params['purpose_key'] = options.purpose;
    return this.api.get<MarketingListCount>(`${this.base(list)}/count`, params);
  }

  /** Up to 20 of the list's people the caller may read. */
  sample(list: string): Observable<MarketingListSample> {
    return this.api.get<MarketingListSample>(`${this.base(list)}/sample`);
  }

  /** Why one person is or is not in the list, step by step. */
  explain(list: string, person: string): Observable<MarketingListExplanation> {
    return this.api.get<MarketingListExplanation>(`${this.base(list)}/explain/${encodeURIComponent(person)}`);
  }

  /** The sends, programmes and journeys that use the list. */
  usage(list: string): Observable<MarketingListUse[]> {
    return this.api
      .get<{ items: MarketingListUse[] }>(`${this.base(list)}/usage`)
      .pipe(map(page => page.items ?? []));
  }
}
