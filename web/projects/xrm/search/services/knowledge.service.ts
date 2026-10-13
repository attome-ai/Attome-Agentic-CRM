import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { Page } from '@attome/base';

/**
 * One row of the authors' knowledge-gap queue (M37 / D-489).
 *
 * The phrase is the backend's scrubbed topic, never the caller's raw question —
 * see D-452 before treating any field here as user text.
 */
export interface GapTopic {
  id: string;
  normalized_phrase: string;
  first_seen_at: string;
  last_seen_at: string;
  hit_count: number;
  status: 'open' | 'addressed' | 'dismissed';
  /** The content page that addressed this gap, from the 0263 shape. */
  addressed_page_ref: string | null;
  /** The Knowledge Base item that addressed it (D-489). */
  addressed_item_ref: string | null;
}

/**
 * One Knowledge Base collection's coverage (C8,
 * `GET /api/v1/admin/knowledge/coverage`). Counts of what is there, never a
 * projection — see `attome_search::knowledge_coverage`.
 */
export interface CollectionCoverage {
  collection_id: string;
  name?: string | null;
  items_total: number;
  items_published: number;
  /** Waiting in the draft review queue; never chunked (D-489). */
  items_draft: number;
  items_expired: number;
  /** Retrievable (`published`) chunk rows. */
  chunks: number;
  /** The newest chunk write; `null` when there are no chunks. */
  last_indexed_at?: string | null;
  /** `null` when knowledge is lexical-only by configuration. */
  chunks_embedded?: number | null;
  /** Chunks still waiting for a vector from the configured model; `null` when lexical-only. */
  embedding_backlog?: number | null;
}

/** The knowledge indexer's shared state (`.../coverage/indexer`). */
export interface IndexerStatus {
  /** When the search drain last advanced over the change feed. */
  drain_last_advanced_at?: string | null;
  /** The model chunk vectors are written with; `null` when lexical-only. */
  embedding_model?: string | null;
}

/**
 * The typed client for the knowledge surfaces (D-489).
 *
 * Deliberately hand-typed rather than pulled from the generated contract: the
 * gap queue is an admin tool whose shape is defined by `knowledge_gap_topic`,
 * and coupling it to a full generated document would make one page's build depend
 * on every route in the platform. The route itself is still in `openapi.json`.
 */
@Injectable({ providedIn: 'root' })
export class KnowledgeService {
  private readonly api = inject(ApiService);

  /** The queue, most recently seen first. `status` omitted means the whole queue. */
  listGaps(opts?: { status?: GapTopic['status']; page?: number; pageSize?: number }): Observable<Page<GapTopic>> {
    const params: Record<string, string> = {};
    if (opts?.status) params['status'] = opts.status;
    if (opts?.page !== undefined) params['page'] = String(opts.page);
    if (opts?.pageSize !== undefined) params['page_size'] = String(opts.pageSize);
    return this.api.get<Page<GapTopic>>('/api/v1/admin/knowledge/gaps', params);
  }

  /** One page of live collections with their coverage. One-based (D-347). */
  coverage(page = 1, pageSize = 100): Observable<Page<CollectionCoverage>> {
    return this.api.get<Page<CollectionCoverage>>('/api/v1/admin/knowledge/coverage', {
      page: String(page),
      page_size: String(pageSize),
    });
  }

  indexerStatus(): Observable<IndexerStatus> {
    return this.api.get<IndexerStatus>('/api/v1/admin/knowledge/coverage/indexer');
  }

  /**
   * Sets one topic's triage state. `addressedItemRef` is meaningful only for
   * `addressed`; the backend clears it for every other status.
   */
  triageGap(
    id: string,
    status: GapTopic['status'],
    addressedItemRef?: string | null,
  ): Observable<GapTopic> {
    return this.api.patch<GapTopic>(`/api/v1/admin/knowledge/gaps/${id}`, {
      status,
      addressed_item_ref: addressedItemRef ?? null,
    });
  }
}
