import { Injectable, inject } from '@angular/core';
import { ApiService } from '@attome/base';
import { Observable } from 'rxjs';

/** A finding of the pre-send check (`crate::precheck::Finding`). */
export interface PrecheckFinding {
  code: string;
  severity: 'error' | 'warning' | 'info';
  guidance_key: string;
  detail?: string | null;
}

/** The pre-send check's answer (`POST /api/v1/marketing/precheck`). */
export interface PrecheckReport {
  score: number;
  passed: boolean;
  findings: PrecheckFinding[];
}

/** What the pre-send check reads. */
export interface PrecheckBody {
  html: string;
  text?: string | null;
  recipients?: number;
  never_mailed?: number;
  invalid?: number;
}

/** An alert the daily evaluation raised (E6-T10). */
export interface DeliverabilityAlert {
  day: string;
  subject: string;
  kind: string;
  value: number;
  threshold: number;
  guidance_key: string;
}

export interface ProviderDay {
  day: string;
  mailbox_provider: string;
  sent: number;
  delivered: number;
  bounced: number;
  complaints: number;
}

export interface SendTotals {
  send_ref: string;
  sent: number;
  delivered: number;
  bounced: number;
  complaints: number;
  opened: number;
  clicked: number;
}

export interface BlocklistStatus {
  target: string;
  target_kind: string;
  list_name: string;
  listed: boolean;
  checked_at: string;
}

export interface DmarcShare {
  domain: string;
  messages: number;
  passed: number;
}

/** `GET /api/v1/marketing/deliverability/overview`. */
export interface DeliverabilityOverview {
  days: number;
  bounce_limit: number;
  complaint_limit: number;
  providers: ProviderDay[];
  sends: SendTotals[];
  alerts: DeliverabilityAlert[];
  blocklist: BlocklistStatus[];
  dmarc: DmarcShare[];
}

/** E6's deliverability routes. */
@Injectable({ providedIn: 'root' })
export class DeliverabilityService {
  private readonly api = inject(ApiService);

  /** The dashboard's figures over the last `days` days (1-90). */
  overview(days: number): Observable<DeliverabilityOverview> {
    return this.api.get<DeliverabilityOverview>('/api/v1/marketing/deliverability/overview', { days: String(days) });
  }

  /** Scores a message before it is sent; nothing is sent or stored. */
  precheck(body: PrecheckBody): Observable<PrecheckReport> {
    return this.api.post<PrecheckReport>('/api/v1/marketing/precheck', body);
  }
}
