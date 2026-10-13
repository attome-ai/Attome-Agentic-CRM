import { inject, Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents, Page } from '@attome/base';
import { AdminHttp } from './admin-http';

/**
 * Solution 7 Phase 2 (D-788 Topic 14, D-791; `SOLUTION-7-PHASE-2-DESIGN.md`
 * §9.3, §10) — the release report: what a release changed on this
 * deployment that an administrator should know about, and the decisions the
 * administrator can take (Accept, Use mine, Restore, Dismiss).
 *
 * Routes: `crates/engine/attome-api/src/admin/release_report.rs`. Items never
 * expire and nothing here blocks a release (Topic 15 #4).
 *
 * The wire types are the generated `ApiComponents['schemas']`, narrowed only
 * where the generated document leaves a JSON object untyped.
 */

/** `attome_core::release_report::ItemKind` (the table's CHECK). */
export const REPORT_ITEM_KINDS = [
  'conflict', 'conversion_nulled', 'field_deleted',
  'customer_object_adjusted', 'customer_object_removed',
  'breaking_api_change', 'choice_removed_in_use', 'required_empty',
] as const;
export type ReportItemKind = typeof REPORT_ITEM_KINDS[number];

/** `attome_core::release_report::ItemStatus`. */
export const REPORT_ITEM_STATUSES = [
  'open', 'info', 'accepted', 'used_mine', 'restored', 'dismissed', 'superseded', 'expired',
] as const;
export type ReportItemStatus = typeof REPORT_ITEM_STATUSES[number];

/** `attome_core::release_report::ReportSource`. */
export const RELEASE_REPORT_SOURCES = ['boot', 'admin', 'replay', 'change'] as const;
export type ReleaseReportSource = typeof RELEASE_REPORT_SOURCES[number];

/** `building | ready`. */
export const RELEASE_REPORT_STATUSES = ['building', 'ready'] as const;
export type ReleaseReportStatus = typeof RELEASE_REPORT_STATUSES[number];

/** Kinds whose values sit in the recovery archive (`ItemKind::archive_backed`). */
export const ARCHIVE_BACKED_KINDS: readonly ReportItemKind[] = ['conversion_nulled', 'field_deleted'];

/** `source` is a `ReleaseReportSource`, `status` a `ReleaseReportStatus`. */
export type ReleaseReport = ApiComponents['schemas']['ReleaseReport'];

/** Narrowed: the closed `kind`/`status` sets, and `detail` (generated as `Record<string, never>`). */
export type ReportItem = Omit<ApiComponents['schemas']['ReportItem'], 'kind' | 'status' | 'detail'> & {
  kind:   ReportItemKind | string;
  status: ReportItemStatus | string;
  /** Counts, names and what changed; never record values. */
  detail: Record<string, unknown>;
};

/** A conflict's sealed values (`attome_core::release_report::ConflictValues`). */
export interface ConflictValues {
  /** The customer's value (kept). */
  theirs: unknown;
  /** Our value. */
  ours:   unknown;
  /** The record's business key. */
  key?:   unknown;
}

/** Narrowed: `values` is generated as `Record<string, never>`; it is a conflict's `ConflictValues`. */
export type ReportItemView = ReportItem
  & Omit<ApiComponents['schemas']['ReportItemView'], keyof ApiComponents['schemas']['ReportItem'] | 'values'>
  & { values?: ConflictValues | null };

export type ReleaseReportSummary = ApiComponents['schemas']['ReleaseReportSummary'];

export type RestoreCounts = ApiComponents['schemas']['RestoreCounts'];

/** Narrowed: `item` is the narrowed `ReportItem` (typed `detail`). */
export type ItemRestoreResult = Omit<ApiComponents['schemas']['ItemRestoreResult'], 'item'> & { item: ReportItem };

export interface ReportFilter {
  status?: ReleaseReportStatus;
  source?: ReleaseReportSource;
}

export interface ItemFilter {
  kind?:   ReportItemKind;
  status?: ReportItemStatus;
  /** Entity logical name. */
  entity?: string;
}

/** The generic record read, for the record's current `row_version`. */
type EntityRecordResponse = ApiComponents['schemas']['EntityRecordResponse'];

const BASE = '/api/v1/admin/metadata';

function pageParams(page: number, pageSize: number): Record<string, string> {
  return { page: String(page), page_size: String(pageSize) };
}

@Injectable({ providedIn: 'root' })
export class ReleaseReportService {
  private readonly api  = inject(ApiService);
  private readonly http = inject(AdminHttp);

  /** Reports, newest first. One-based paging (D-731). */
  listReports(filter: ReportFilter = {}, page = 1, pageSize = 20): Observable<Page<ReleaseReport>> {
    const params = pageParams(page, pageSize);
    if (filter.status) params['status'] = filter.status;
    if (filter.source) params['source'] = filter.source;
    return this.api.get<Page<ReleaseReport>>(`${BASE}/release-reports`, params);
  }

  /** Open items by kind, the last release and reports still building. */
  summary(): Observable<ReleaseReportSummary> {
    return this.api.get<ReleaseReportSummary>(`${BASE}/release-reports/summary`);
  }

  getReport(reportId: string): Observable<ReleaseReport> {
    return this.api.get<ReleaseReport>(`${BASE}/release-reports/${encodeURIComponent(reportId)}`);
  }

  /** A report's items, oldest first. One-based paging. */
  listItems(reportId: string, filter: ItemFilter = {}, page = 1, pageSize = 25): Observable<Page<ReportItemView>> {
    const params = pageParams(page, pageSize);
    if (filter.kind)   params['kind'] = filter.kind;
    if (filter.status) params['status'] = filter.status;
    if (filter.entity) params['entity'] = filter.entity;
    return this.api.get<Page<ReportItemView>>(
      `${BASE}/release-reports/${encodeURIComponent(reportId)}/items`, params,
    );
  }

  /** Conflict: keep the customer's value. `If-Match` is the item's `row_version`. */
  accept(item: Pick<ReportItem, 'id' | 'row_version'>): Observable<ReportItem> {
    return this.decide(item, 'accept', {});
  }

  /**
   * Conflict: write our value now. For a record conflict
   * `recordRowVersion` is the record's `row_version` as the caller read it
   * (the write is refused with 409 when the record changed since); a rule
   * conflict sends none.
   */
  useMine(item: Pick<ReportItem, 'id' | 'row_version'>, recordRowVersion?: number): Observable<ReportItem> {
    const body = recordRowVersion === undefined ? {} : { record_row_version: recordRowVersion };
    return this.decide(item, 'use-mine', body);
  }

  /** Any open or info item: the administrator has seen it. */
  dismiss(item: Pick<ReportItem, 'id' | 'row_version'>): Observable<ReportItem> {
    return this.decide(item, 'dismiss', {});
  }

  /**
   * Archive-backed item: restore its values (empty fields only). Not
   * `If-Match`-guarded (a retry skips what is restored); repeat while
   * `remaining > 0`.
   */
  restore(itemId: string): Observable<ItemRestoreResult> {
    return this.api.post<ItemRestoreResult>(
      `${BASE}/release-report-items/${encodeURIComponent(itemId)}/restore`, {},
    );
  }

  /** The record's current `row_version` (Use mine on a record conflict). */
  recordRowVersion(entity: string, recordId: string): Observable<number> {
    return this.api.get<EntityRecordResponse>(
      `/api/v1/${encodeURIComponent(entity)}/${encodeURIComponent(recordId)}`,
    ).pipe(map(r => r.row_version));
  }

  private decide(
    item: Pick<ReportItem, 'id' | 'row_version'>,
    action: 'accept' | 'use-mine' | 'dismiss',
    body: Record<string, unknown>,
  ): Observable<ReportItem> {
    return this.http.request<ReportItem>(
      'POST',
      `${BASE}/release-report-items/${encodeURIComponent(item.id)}/${action}`,
      { body, ifMatch: item.row_version },
    ).pipe(map(res => res.body as ReportItem));
  }
}
