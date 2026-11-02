import { Injectable, inject } from '@angular/core';
import { SdkService } from '@attome/base';
import { Observable, map } from 'rxjs';

/** A tracked site (`marketing_tracked_site`), as the screen needs it. */
export interface TrackedSite {
  id: string;
  name: string | null;
  site_key: string;
  domains: string | null;
  enabled: boolean;
}

/** A session seen in the last five minutes (`GET /api/v1/marketing/tracking/live`, E14-T9). */
export interface LiveVisitor {
  session_id: string;
  visitor_id: string;
  contact_ref?: string | null;
  lead_ref?: string | null;
  started_at: string;
  last_seen_at: string;
  page_count: number;
  current_url?: string | null;
  utm_source?: string | null;
}

export interface ReportRow {
  label: string;
  visits: number;
}

/** A site's visits over a window (`GET /api/v1/marketing/tracking/report`, E14-T12). */
export interface TrackingReport {
  site: string;
  days: number;
  visits: number;
  identified: number;
  sources: ReportRow[];
  landing_pages: ReportRow[];
  campaigns: ReportRow[];
}

interface Page<T> {
  items: T[];
  total: number;
}

/** A record of the query route as a tracked site. Pure. */
export function toSite(r: Record<string, unknown>): TrackedSite | null {
  const key = typeof r['site_key'] === 'string' ? r['site_key'].trim() : '';
  if (!key) return null;
  const text = (v: unknown) => (typeof v === 'string' && v.trim() ? v : null);
  return {
    id: String(r['id'] ?? ''),
    name: text(r['name']),
    site_key: key,
    domains: text(r['domains']),
    enabled: r['enabled'] === true,
  };
}

/** The tracking routes the screen reads (E14-T12). */
@Injectable({ providedIn: 'root' })
export class TrackingService {
  private readonly sdk = inject(SdkService);

  sites(): Observable<TrackedSite[]> {
    return this.sdk
      .post<{ data?: { records?: Record<string, unknown>[] } }>('/api/v1/query/execute', {
        body: { entity: 'marketing_tracked_site', page_size: 100 },
      })
      .pipe(map(resp => (resp.data?.records ?? []).map(toSite).filter((s): s is TrackedSite => s !== null)));
  }

  live(site: string): Observable<LiveVisitor[]> {
    return this.sdk
      .get<Page<LiveVisitor>>('/api/v1/marketing/tracking/live', { query: { site, page_size: 50 } })
      .pipe(map(page => page.items));
  }

  report(site: string, days: number): Observable<TrackingReport> {
    return this.sdk.get<TrackingReport>('/api/v1/marketing/tracking/report', { query: { site, days } });
  }
}
