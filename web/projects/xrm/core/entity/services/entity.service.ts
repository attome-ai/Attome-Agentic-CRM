import { DestroyRef, inject, Injectable } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { catchError, map, Observable, shareReplay, throwError } from 'rxjs';
import { ApiComponents, ApiService, LangService, ListResponse } from '@attome/base';
import { EntityRecord, EntitySchema, ListFilter, ListParams } from '@attome/xrm';
import { EntityMetadataChangeService } from '@attome/xrm/core/admin/data';
import { QueryService } from '@attome/xrm/core/query/data';

/**
 * P-api-contract Phase 2 — this service's single-record calls are typed from
 * the generated OpenAPI document instead of a hand-written interface, which is
 * the plan's proof that the codegen pipeline is actually usable end to end.
 *
 * It also closed two real drifts the hand-written `EntityRecord` had: the
 * backend's response carries a `lookups` map (P-entity-contract-hardening) the
 * interface never declared, and `created_at`/`updated_at` are nullable on the
 * wire but were typed as required `string`.
 *
 * `list()` below deliberately keeps returning the hand-written `EntityRecord`:
 * it is not a `/api/v1/{entity}/{id}` response at all, it is rows from
 * `POST /api/v1/query/execute` reshaped client-side (D-036). Migrating the
 * remaining hand-written services is incremental follow-up work, not this
 * change (P-api-contract §4).
 */
export type EntityRecordResponse = ApiComponents['schemas']['EntityRecordResponse'];

/** One item of `POST /api/v1/{entity}/bulk` — `crates/engine/attome-api/src/bulk.rs::BulkRecordEnvelope`. */
export type BulkRecordEnvelope   = ApiComponents['schemas']['BulkRecordEnvelope'];
export type BulkOperationResponse = ApiComponents['schemas']['BulkOperationResponse'];
export type BulkOperationStatus   = ApiComponents['schemas']['BulkOperationStatus'];

/** M12 (data management) — `POST /api/v1/{entity}/export` and its status poll,
 * `crates/engine/attome-api/src/data_export.rs`. */
export type ExportEnqueueResponse = ApiComponents['schemas']['ExportEnqueueResponse'];
export type ExportStatusResponse  = ApiComponents['schemas']['ExportStatusResponse'];

/** M07/M64 (kanban) — `GET/POST /api/v1/{entity}/{id}/transition[s]`,
 * `crates/engine/attome-state/src/record_routes.rs`. The kanban board offers ONLY
 * the transitions this endpoint returns and never computes legality
 * client-side — `POST .../transition` is the sole enforcement point
 * (`attome_core::check_transition`), same as a raw `PATCH`. */
export type AvailableTransition      = ApiComponents['schemas']['AvailableTransition'];
export type TransitionRequestBody    = ApiComponents['schemas']['TransitionRequestBody'];
export type TransitionResult         = ApiComponents['schemas']['TransitionResult'];
export type PaginatedAvailableTransitions =
  ApiComponents['schemas']['PaginatedResponse_AvailableTransition'];

/** `recycle_bin::DeleteImpact` (A18-T4). */
export interface DeleteImpact {
  cascades: { entity: string; field: string; count: number }[];
  blocked_by: { entity: string; field: string; count: number }[];
  orphaned: { entity: string; field: string; count: number }[];
  hidden_dependents: boolean;
  reason_required: boolean;
}

@Injectable({ providedIn: 'root' })
export class EntityService {
  private readonly api   = inject(ApiService);
  private readonly query = inject(QueryService);
  private readonly lang  = inject(LangService);

  // ── Schema ────────────────────────────────────────────────────────────────

  // PERF-3 (PLATFORM-REVIEW-2026-08-24 section 4): `getSchema` used to be a bare
  // HTTP call, and `EngineFormBase.ngOnInit` calls it unconditionally on every form
  // open - so every navigation into any of the ~30 entity screens refetched
  // near-static data. Schemas only change when an admin edits metadata.
  //
  // Cache contract:
  //   - Source of truth: `GET /api/v1/schema/{logicalname}?locale=`, always.
  //   - Key: `"{entityName}::{locale}"` (M05/D-426) - a language toggle mid-
  //     session must not serve the other language's cached labels, so the
  //     active `LangService` locale is part of the cache key, not just the
  //     query string.
  //   - Invalidation: `EntityMetadataChangeService.changed$` clears the whole
  //     map the moment an admin creates/updates/deletes an entity, attribute,
  //     or metadata label in *this* browser tab.
  //   - TTL: the backstop for the edit this tab cannot observe - another tab,
  //     another operator, or a bundle applied server-side. `SCHEMA_TTL_MS`
  //     bounds how long such a change can go unseen.
  //   - Failure: a failed request is evicted before it is replayed, so an error
  //     is never cached - the next caller retries against the backend.
  //   - Cold start: empty; the first form open per entity/locale pays the request.

  /**
   * How long a cached schema is served without revalidating. Only covers
   * metadata edits this tab never saw - a local edit invalidates immediately.
   */
  private static readonly SCHEMA_TTL_MS = 5 * 60 * 1000;

  private readonly schemaCache =
    new Map<string, { at: number; schema$: Observable<EntitySchema> }>();

  constructor() {
    inject(EntityMetadataChangeService).changed$
      .pipe(takeUntilDestroyed(inject(DestroyRef)))
      .subscribe(() => this.invalidateSchema());
  }

  /** M05/D-426: the BCP-47 tag threaded to `?locale=` — `LangService.intlLocale()`
   * (e.g. `"ar-SA"`), never the bare `Lang` code, so it resolves through the same
   * requested-locale -> deployment-default -> base-name chain the backend implements. */
  private cacheKey(entityName: string): string {
    return `${entityName}::${this.lang.intlLocale()}`;
  }

  getSchema(entityName: string): Observable<EntitySchema> {
    const key = this.cacheKey(entityName);
    const hit = this.schemaCache.get(key);
    if (hit && Date.now() - hit.at < EntityService.SCHEMA_TTL_MS) {
      return hit.schema$;
    }
    const locale = this.lang.intlLocale();
    const schema$ = this.api
      .get<EntitySchema>(`/api/v1/schema/${entityName}`, { locale })
      .pipe(
        // Evict before the error reaches `shareReplay`, so a transient failure is
        // not replayed to every later caller until the TTL expires.
        catchError((err: unknown) => {
          this.schemaCache.delete(key);
          return throwError(() => err);
        }),
        shareReplay({ bufferSize: 1, refCount: false }),
      );
    this.schemaCache.set(key, { at: Date.now(), schema$ });
    return schema$;
  }

  /**
   * Drops cached schemas - one entity (every locale variant of it), or all of
   * them when `entityName` is omitted. Called automatically on metadata
   * mutations; exposed for a caller that knows the backend's metadata moved
   * for a reason this tab cannot see.
   */
  invalidateSchema(entityName?: string): void {
    if (entityName === undefined) {
      this.schemaCache.clear();
      return;
    }
    const prefix = `${entityName}::`;
    for (const key of this.schemaCache.keys()) {
      if (key.startsWith(prefix)) this.schemaCache.delete(key);
    }
  }

  // ── Records ───────────────────────────────────────────────────────────────

  // D-036: entity lists go through POST /api/v1/query/execute (the entity's
  // seeded default query) — the platform has no generic /api/v1/list endpoint.
  list(entityName: string, params?: ListParams): Observable<ListResponse<EntityRecord>> {
    const limit  = params?.limit  ?? 50;
    const offset = params?.offset ?? 0;
    const sort   = params?.sorts?.[0];
    return this.query.execute({
      entity:    entityName,
      page:      Math.floor(offset / limit) + 1,
      page_size: limit,
      order_by:  sort?.field ?? '',
      order_dir: sort?.dir   ?? 'asc',
      filters:   params?.filters ?? [],
      // P-stored-query-containment (D-126): query/execute's default flipped
      // to keyset/cursor mode (no total) — this view does page-number
      // pagination and needs the real count, so it must opt in explicitly
      // now instead of relying on the old default.
      include_total: true,
    }).pipe(
      map(res => ({
        data: res.data.records.map(r => ({
          id:          String(r['id'] ?? ''),
          entity_id:   '',
          data:        r,
          created_at:  String(r['created_at'] ?? ''),
          updated_at:  String(r['modified_at'] ?? r['created_at'] ?? ''),
          row_version: Number(r['row_version'] ?? 0),
        })),
        meta: { total: res.data.total ?? 0, limit, offset },
      })),
    );
  }

  get(entityName: string, id: string): Observable<EntityRecordResponse> {
    return this.api.get<EntityRecordResponse>(`/api/v1/${entityName}/${id}`);
  }

  create(entityName: string, data: Record<string, unknown>): Observable<EntityRecordResponse> {
    return this.api.post<EntityRecordResponse>(`/api/v1/${entityName}`, data);
  }

  update(
    entityName: string,
    id: string,
    patch: Record<string, unknown>,
    rowVersion?: number,
  ): Observable<EntityRecordResponse> {
    return this.api.patch<EntityRecordResponse>(`/api/v1/${entityName}/${id}`, patch, rowVersion);
  }

  /**
   * Soft-deletes a record into the recycle bin. A18: `operationId` groups
   * deletes so {@link restoreOperation} can undo them together; `reason` is
   * kept with the deletion (and required when the entity's bin setting says so).
   */
  delete(entityName: string, id: string, options: { operationId?: string; reason?: string } = {}): Observable<void> {
    const reason = options.reason?.trim();
    const query = reason ? `?reason=${encodeURIComponent(reason)}` : '';
    return this.api.delete(`/api/v1/${entityName}/${id}${query}`, { operationId: options.operationId });
  }

  /** A18-T4: what deleting `ids` would cascade to or be blocked by; changes nothing. */
  deleteImpact(entityName: string, ids: string[]): Observable<DeleteImpact> {
    return this.api.post<DeleteImpact>(`/api/v1/${entityName}/delete-impact`, { ids });
  }

  /** A18: restores every record one delete operation put in the bin. */
  restoreOperation(operationId: string): Observable<{ restored: number; failed: { entity: string; id: string; code: string }[] }> {
    return this.api.post(`/api/v1/bin/operations/${encodeURIComponent(operationId)}/restore`, {});
  }

  /** B7-T3: copies a record through the ordinary create; returns the copy's id. */
  clone(entityName: string, id: string): Observable<{ id: string | null }> {
    return this.api.post<{ id: string | null }>(
      `/api/v1/${encodeURIComponent(entityName)}/${encodeURIComponent(id)}/clone`, {},
    );
  }

  /** A28-T2: the values a new record of `entityName` starts with, by field. */
  newDefaults(entityName: string): Observable<Record<string, unknown>> {
    return this.api.get<Record<string, unknown>>(`/api/v1/${encodeURIComponent(entityName)}/new`);
  }

  /** B2-T3: one field's change history on a record, newest first. */
  fieldHistory(
    entityName: string,
    id: string,
    field: string,
  ): Observable<ApiComponents['schemas']['CursorPage_RecordHistoryChange']> {
    return this.api.get<ApiComponents['schemas']['CursorPage_RecordHistoryChange']>(
      `/api/v1/${encodeURIComponent(entityName)}/${encodeURIComponent(id)}/history`,
      { field, page_size: '50' },
    );
  }

  restore(entityName: string, id: string): Observable<EntityRecordResponse> {
    return this.api.post<EntityRecordResponse>(`/api/v1/${entityName}/${id}/restore`, {});
  }

  // ── State transitions (M07/M64 kanban) ───────────────────────────────────

  /** The transitions THIS caller may apply to THIS record right now — the
   * kanban board's drop targets, and nothing else ever decides that. */
  listTransitions(entityName: string, id: string): Observable<PaginatedAvailableTransitions> {
    return this.api.get<PaginatedAvailableTransitions>(`/api/v1/${entityName}/${id}/transitions`);
  }

  /** The API enforces the transition (`check_transition`) — a rejected edge
   * is a normal `422`, surfaced to the caller like any other validation
   * error, never pre-filtered away client-side beyond what `listTransitions`
   * already offered. */
  transition(
    entityName: string,
    id: string,
    body: TransitionRequestBody,
  ): Observable<TransitionResult> {
    return this.api.post<TransitionResult>(`/api/v1/${entityName}/${id}/transition`, body);
  }

  hardDelete(entityName: string, id: string): Observable<void> {
    return this.api.delete(`/api/v1/${entityName}/${id}/hard-delete`);
  }

  // ── M:M relationships (M01 Core P3 gap, D-455) ───────────────────────────

  /** Every live record on `relationship`'s other side currently linked to
   * `id`, paginated. `relationship` names an `relationship_info`
   * row — see `EntitySchema.relationships` (`getSchema`) for the set
   * configured for `entityName`. */
  listRelated(
    entityName: string,
    id: string,
    relationship: string,
    page = 1,
    pageSize = 50,
  ): Observable<{ items: EntityRecordResponse[]; total: number; page: number; page_size: number }> {
    return this.api.get<{ items: EntityRecordResponse[]; total: number; page: number; page_size: number }>(
      `/api/v1/${entityName}/${id}/related/${relationship}`,
      { page: String(page), page_size: String(pageSize) },
    );
  }

  /** Idempotent (upsert-by-natural-key): linking an already-linked pair is a
   * no-op, not a conflict. Requires `update` privilege on BOTH sides. */
  linkRelated(entityName: string, id: string, relationship: string, otherId: string): Observable<void> {
    return this.api.post(`/api/v1/${entityName}/${id}/related/${relationship}`, { id: otherId });
  }

  /** `?id=`, not a request body — `DELETE` conventionally carries none, and
   * `ApiService.delete` has no body-sending variant (see the Rust handler's
   * own doc comment for why this endpoint took the query-param route
   * instead of growing that capability for one caller). */
  unlinkRelated(entityName: string, id: string, relationship: string, otherId: string): Observable<void> {
    return this.api.delete(`/api/v1/${entityName}/${id}/related/${relationship}?id=${otherId}`);
  }

  // ── Bulk operations ───────────────────────────────────────────────────────

  /**
   * Enqueues one durable bulk `update` (PROD-12). Every envelope must carry
   * `id` and `expected_row_version` — the engine's update path refuses an
   * envelope without them (`bulk.rs::validate_record_envelope`), which is why
   * the grid reads each record before calling this rather than trusting the
   * list page's rows (`query/execute` projects only the stored query's
   * columns, so `row_version` is not reliably present there). The default
   * `batch_mode` ("partial") is deliberate: it matches the per-record
   * fan-out the other selection actions already use.
   */
  bulkUpdate(entityName: string, records: BulkRecordEnvelope[]): Observable<BulkOperationResponse> {
    const body: ApiComponents['schemas']['BulkRequestBody'] = { operation: 'update', records };
    return this.api.post<BulkOperationResponse>(`/api/v1/${entityName}/bulk`, body);
  }

  bulkStatus(entityName: string, bulkOperationId: string): Observable<BulkOperationStatus> {
    return this.api.get<BulkOperationStatus>(`/api/v1/${entityName}/bulk/${bulkOperationId}`);
  }

  // ── Export (M12) ─────────────────────────────────────────────────────────

  /**
   * Enqueues a durable, permission-filtered export
   * (`attome_api::data_export`) — row and field security are always applied
   * server-side, the same as an ordinary list read (D-408). `columns` empty
   * means "every column the caller can currently read."
   */
  exportRecords(
    entityName: string,
    format:     'csv' | 'xlsx' | 'json',
    columns:    readonly string[] = [],
    /** Dashboard drill-through (Phase 3.4): the drill's exact filters, so the
     * file holds the records the drawer listed. */
    filter:     ApiComponents['schemas']['ExportRequestBody']['filter'] = [],
  ): Observable<ExportEnqueueResponse> {
    const body: ApiComponents['schemas']['ExportRequestBody'] = { format, columns: [...columns], filter: [...(filter ?? [])] };
    return this.api.post<ExportEnqueueResponse>(`/api/v1/${entityName}/export`, body);
  }

  exportStatus(entityName: string, exportId: string): Observable<ExportStatusResponse> {
    return this.api.get<ExportStatusResponse>(`/api/v1/${entityName}/export/${exportId}`);
  }

  // ── Lookup search ─────────────────────────────────────────────────────────

  lookupSearch(
    entityName:   string,
    search:       string,
    displayField: string | null,
  ): Observable<ListResponse<EntityRecord>> {
    const filters: ListFilter[] = [];
    if (search.trim() && displayField) {
      filters.push({ field: displayField, op: 'contains', value: search.trim() });
    }
    return this.list(entityName, {
      filters,
      limit: 20,
      sorts: displayField ? [{ field: displayField, dir: 'asc' }] : [],
    });
  }
}
