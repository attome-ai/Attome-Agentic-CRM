import { inject, Injectable } from '@angular/core';
import { Observable, map } from 'rxjs';
import { ApiService } from '@attome/base';

// ── Wire types (mirror attome_service::offering exactly) ─────────────────────

export interface OfferingSummary {
  id:               string;
  name:             string;
  category:         string | null;
  description:      string | null;
  default_priority: string;
  /** `ticket | task | project | workflow:<def>`. */
  fulfilment:       string;
}

export interface CreateWorkRequestFromOfferingRequest {
  title:         string;
  description:   string | null;
  request_type:  string;
  requester_id:  string;
}

export interface CreateWorkRequestFromOfferingResponse {
  work_request_id: string;
  status:           string;
  /** `{public_id}.{secret}` — shown to the requester exactly once. */
  portal_token:     string;
  /** G2-T2: the request's reference, when the reference rule numbered it. */
  reference?:       string | null;
}

/** G2-T4: one work request as the triage board shows it. */
export interface TriageItem {
  id:           string;
  title:        string;
  reference:    string | null;
  status:       string;
  priority:     string | null;
  category:     string | null;
  created_at:   string | null;
  row_version:  number;
}

/** G2-T3: a conversion map the board can convert with. */
export interface ConversionMapOption {
  id:            string;
  name:          string;
  target_entity: string;
}

/** A knowledge passage suggested while a request is written. */
export interface KnowledgeSuggestion {
  item_id: string;
  title:   string;
  passage: string;
}

/** The statuses the triage board shows, in column order. */
export const TRIAGE_STATUSES = ['new', 'triaged', 'converted', 'rejected'] as const;

/** Groups items into the board's columns, newest first in each. Pure. */
export function triageColumns(items: TriageItem[]): Record<string, TriageItem[]> {
  const columns: Record<string, TriageItem[]> = {};
  for (const status of TRIAGE_STATUSES) columns[status] = [];
  for (const item of items) {
    (columns[item.status] ??= []).push(item);
  }
  for (const list of Object.values(columns)) {
    list.sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? ''));
  }
  return columns;
}

function text(value: unknown): string | null {
  return value === null || value === undefined || value === '' ? null : String(value);
}

/**
 * The internal "New Request" picker's client — authenticated, distinct from
 * `ServicePortalService` (which calls the anonymous, bypass
 * `/api/v1/service-portal/*` routes). This one calls the catalog +
 * create-from-offering routes (`attome_service::offering`), which stay
 * license/privilege-gated like any other admin surface.
 */
@Injectable({ providedIn: 'root' })
export class ServiceAdminService {
  private readonly api = inject(ApiService);

  listActiveOfferings(): Observable<OfferingSummary[]> {
    return this.api.get<OfferingSummary[]>('/api/v1/service-offering/active');
  }

  /** G2-T4: the latest work requests, for the triage board (at most 200). */
  listWorkRequests(): Observable<TriageItem[]> {
    return this.api
      .get<{ items: Record<string, unknown>[] }>('/api/v1/service_work_request', {
        select: 'id,title,reference,status,priority,category,created_at,row_version',
        sort: '-created_at',
        page_size: '200',
      })
      .pipe(map(page => (page.items ?? []).map(row => ({
        id: String(row['id']),
        title: text(row['title']) ?? '',
        reference: text(row['reference']),
        status: text(row['status']) ?? 'new',
        priority: text(row['priority']),
        category: text(row['category']),
        created_at: text(row['created_at']),
        row_version: Number(row['row_version'] ?? 0),
      }))));
  }

  /** G2-T4: accept (`triaged`) or reject a request, against its version. */
  setWorkRequestStatus(item: TriageItem, status: 'triaged' | 'rejected'): Observable<unknown> {
    return this.api.patch(`/api/v1/service_work_request/${item.id}`, { status }, item.row_version);
  }

  /** G2-T3: the conversion maps there are. */
  listConversionMaps(): Observable<ConversionMapOption[]> {
    return this.api
      .get<{ items: Record<string, unknown>[] }>('/api/v1/service_conversion_map', {
        select: 'id,name,target_entity',
        sort: 'name',
        page_size: '200',
      })
      .pipe(map(page => (page.items ?? []).map(row => ({
        id: String(row['id']),
        name: text(row['name']) ?? String(row['id']),
        target_entity: text(row['target_entity']) ?? '',
      }))));
  }

  /** G2-T3: converts a request with one map. */
  convertWorkRequest(id: string, mapId: string): Observable<unknown> {
    return this.api.post(`/api/v1/work-request/${id}/convert`, { map_ids: [mapId] });
  }

  /** G2-T4: knowledge passages that match what a request says so far. */
  suggestKnowledge(query: string): Observable<KnowledgeSuggestion[]> {
    return this.api
      .get<{ items: KnowledgeSuggestion[] }>('/api/v1/search/knowledge', { q: query, limit: '3' })
      .pipe(map(page => page.items ?? []));
  }

  createWorkRequestFromOffering(
    offeringId: string,
    body: CreateWorkRequestFromOfferingRequest,
  ): Observable<CreateWorkRequestFromOfferingResponse> {
    return this.api.post<CreateWorkRequestFromOfferingResponse>(
      `/api/v1/service-offering/${offeringId}/create-work-request`,
      body,
    );
  }
}
