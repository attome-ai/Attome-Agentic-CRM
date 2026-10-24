import {
  HttpErrorResponse, HttpEvent, HttpInterceptorFn, HttpRequest, HttpResponse,
} from '@angular/common/http';
import { inject } from '@angular/core';
import { LangService } from '@attome/base';
import type { BusinessRuleClient, EntitySchema } from '@attome/xrm';
import { computeFieldPolicies, fieldKindResolver } from '@attome/xrm/core/entity';
import { Observable, catchError, from, tap, throwError } from 'rxjs';

import { OFFLINE_STORE, OfflineQueueService } from './offline-queue.service';
import { OfflineStore } from './offline-store';
import { OfflineProfileBundle, PROFILE_KEY } from './state-machine';

/** A record as the device keeps it (what `/api/v1/offline/pull` sent, or an offline write). */
type StoredRecord = Record<string, unknown> & { id?: string; row_version?: number };

/** The profile's entities, with the fields the server numbers on create (when the profile names them). */
type ProfileEntity = OfflineProfileBundle['entities'][number] & { autonumber_fields?: string[] };

/** Where a schema answer is kept for offline use. */
export function schemaKey(entity: string): string {
  return `schema:${entity}`;
}

const API = '/api/v1/';

/**
 * What a request asks of the offline data path, or `null` when it cannot be
 * an entity read or write. A first segment is taken as an entity here; the
 * device's profile decides whether it is one it holds. Pure.
 */
export function offlineRoute(method: string, url: string, body: unknown):
  | { kind: 'schema'; entity: string }
  | { kind: 'list'; entity: string }
  | { kind: 'get' | 'update' | 'delete'; entity: string; id: string }
  | { kind: 'create'; entity: string }
  | null {
  let path: string;
  try {
    path = new URL(url, 'http://local/').pathname;
  } catch {
    return null;
  }
  if (!path.startsWith(API)) return null;
  const parts = path.slice(API.length).split('/').filter(Boolean).map(decodeURIComponent);
  if (parts[0] === 'schema' && parts.length === 2 && method === 'GET') return { kind: 'schema', entity: parts[1] };
  if (parts[0] === 'query' && parts[1] === 'execute' && method === 'POST') {
    const entity = (body as { entity?: unknown } | null)?.entity;
    return typeof entity === 'string' && entity ? { kind: 'list', entity } : null;
  }
  if (!/^[a-z][a-z0-9_]*$/.test(parts[0] ?? '')) return null;
  if (parts.length === 1 && method === 'POST') return { kind: 'create', entity: parts[0] };
  if (parts.length === 2) {
    if (method === 'GET') return { kind: 'get', entity: parts[0], id: parts[1] };
    if (method === 'PATCH') return { kind: 'update', entity: parts[0], id: parts[1] };
    if (method === 'DELETE') return { kind: 'delete', entity: parts[0], id: parts[1] };
  }
  return null;
}

/** The rule errors a write would raise, as the server's `validation_error` details. Pure. */
export function ruleErrors(
  rules: readonly BusinessRuleClient[],
  fields: EntitySchema['fields'],
  record: Readonly<Record<string, unknown>>,
): { field: string; code: string; message: string }[] {
  const { errors } = computeFieldPolicies(rules, record, fieldKindResolver(fields));
  const out: { field: string; code: string; message: string }[] = [];
  for (const [field, messages] of errors) {
    for (const m of messages) if (m.severity !== 'warning') out.push({ field, code: 'rule_violation', message: m.message || m.ruleName });
  }
  return out;
}

function respond<T>(body: T, status = 200): HttpResponse<T> {
  return new HttpResponse({ status, body });
}

function refuse(status: number, error: string, message: string, details?: unknown): HttpErrorResponse {
  return new HttpErrorResponse({ status, error: { error, message, details } });
}

const isNetworkError = (e: unknown) => e instanceof HttpErrorResponse && e.status === 0;

/**
 * B18-T8: entity reads and writes keep working without a network. While the
 * browser is offline, or when a request fails for want of one, a request for
 * an entity the device's offline profile holds is answered on the device:
 *
 * - `GET /api/v1/{entity}/{id}` and entity-mode `POST /api/v1/query/execute`
 *   from the device's records (a record not on the device is a 404 with code
 *   `not_on_device`);
 * - `POST`, `PATCH` and `DELETE` are checked against the entity's business
 *   rules (the rules of its last schema, with the same evaluator the form
 *   runs; a failure is the server's 422 `validation_error` shape, so the form
 *   shows it at once), then queued for the sync and answered with the
 *   optimistic record; fields the server numbers on create show as pending;
 * - `GET /api/v1/schema/{entity}` from the copy kept the last time it loaded.
 *
 * Online, everything passes through; schema answers are kept for later.
 */
export const offlineDataInterceptor: HttpInterceptorFn = (req, next) => {
  const route = offlineRoute(req.method, req.url, req.body);
  if (!route) return next(req);
  const offline = answerOffline(req);
  if (typeof navigator !== 'undefined' && navigator.onLine === false) return offline;
  const store = inject(OFFLINE_STORE);
  return next(req).pipe(
    tap(event => keepSchemaIn(store, req, event)),
    catchError((e: unknown) => (isNetworkError(e) ? offline : throwError(() => e))),
  );
};

/**
 * The device's answer to `req`, for a caller that already knows the
 * network is gone. Call in an injection context. A request that is not an
 * entity read or write fails as the network did.
 */
export function answerOffline(req: HttpRequest<unknown>): Observable<HttpEvent<unknown>> {
  const route = offlineRoute(req.method, req.url, req.body);
  if (!route) return throwError(() => new HttpErrorResponse({ status: 0, url: req.url }));
  const store = inject(OFFLINE_STORE);
  const queue = inject(OfflineQueueService);
  const lang = inject(LangService);
  return serveOffline(route, req, store, queue, lang);
}

/** Keeps a schema answer for offline use. Call in an injection context. */
export function keepSchema(req: HttpRequest<unknown>, event: HttpEvent<unknown>): void {
  keepSchemaIn(inject(OFFLINE_STORE), req, event);
}

function keepSchemaIn(store: OfflineStore, req: HttpRequest<unknown>, event: HttpEvent<unknown>): void {
  const route = offlineRoute(req.method, req.url, req.body);
  if (route?.kind !== 'schema' || !(event instanceof HttpResponse) || !event.ok) return;
  void store.put('meta', schemaKey(route.entity), event.body).catch(() => undefined);
}

function serveOffline(
  route: NonNullable<ReturnType<typeof offlineRoute>>,
  req: HttpRequest<unknown>,
  store: OfflineStore,
  queue: OfflineQueueService,
  lang: LangService,
): Observable<HttpEvent<unknown>> {
  return from((async (): Promise<HttpEvent<unknown>> => {
    if (route.kind === 'schema') {
      const schema = await store.get<EntitySchema>('meta', schemaKey(route.entity));
      if (schema) return respond(schema);
      throw refuse(404, 'not_on_device', lang.translate('offline.notOnDevice'));
    }
    const profile = await store.get<OfflineProfileBundle>('meta', PROFILE_KEY);
    const entity = profile?.entities.find(e => e.entity === route.entity) as ProfileEntity | undefined;
    // Not an entity the device holds (or not an entity at all): it fails as the network did.
    if (!entity) throw new HttpErrorResponse({ status: 0, url: req.url });

    if (route.kind === 'get') {
      const record = await store.getRecord<StoredRecord>(route.entity, route.id);
      if (!record) throw refuse(404, 'not_on_device', lang.translate('offline.notOnDevice'));
      return respond(asResponse(route.id, record));
    }
    if (route.kind === 'list') return respond(await listResponse(store, route.entity, req.body));

    const schema = await store.get<EntitySchema>('meta', schemaKey(route.entity));
    const body = ((req.body ?? {}) as Record<string, unknown>);
    if (route.kind === 'create') {
      const id = queue.newRecordId();
      const record: StoredRecord = { ...body, id, row_version: 0 };
      check(schema, record, lang);
      for (const f of entity.autonumber_fields ?? []) {
        if (record[f] === undefined || record[f] === null || record[f] === '') record[f] = lang.translate('offline.pendingNumber');
      }
      await queue.enqueue({ kind: 'create', entity: route.entity, id, changed: body });
      await store.putRecord(route.entity, id, record);
      return respond(asResponse(id, record), 201);
    }
    const stored = await store.getRecord<StoredRecord>(route.entity, route.id);
    if (!stored) throw refuse(404, 'not_on_device', lang.translate('offline.notOnDevice'));
    if (route.kind === 'update') {
      const merged: StoredRecord = { ...stored, ...body };
      check(schema, merged, lang);
      const base: Record<string, unknown> = {};
      for (const k of Object.keys(body)) base[k] = stored[k];
      await queue.enqueue({
        kind: 'update', entity: route.entity, id: route.id,
        base_row_version: Number(stored.row_version ?? 0), changed: body, base_values: base,
      });
      await store.putRecord(route.entity, route.id, merged);
      return respond(asResponse(route.id, merged));
    }
    await queue.enqueue({ kind: 'delete', entity: route.entity, id: route.id, base_row_version: Number(stored.row_version ?? 0) });
    await store.deleteRecord(route.entity, route.id);
    return respond(null, 204);
  })());
}

/** Refuses a write the entity's rules refuse, with the server's 422 shape. */
function check(schema: EntitySchema | null, record: Record<string, unknown>, lang: LangService): void {
  if (!schema?.business_rules?.length) return;
  const errors = ruleErrors(schema.business_rules, schema.fields, record);
  if (errors.length) throw refuse(422, 'validation_error', lang.translate('offline.ruleFailed'), errors);
}

/** A stored record as `GET /api/v1/{entity}/{id}` answers. */
function asResponse(id: string, record: StoredRecord): Record<string, unknown> {
  const data = (record['data'] && typeof record['data'] === 'object') ? record['data'] as Record<string, unknown> : record;
  return {
    id, data, row_version: Number(record.row_version ?? 0),
    created_at: record['created_at'] ?? null, updated_at: record['modified_at'] ?? record['updated_at'] ?? null,
  };
}

/** The device's records of `entity` as `query/execute` answers: equality filters, one page. */
async function listResponse(store: OfflineStore, entity: string, body: unknown): Promise<Record<string, unknown>> {
  const q = (body ?? {}) as { page?: number; page_size?: number; filters?: { field: string; op?: string; value?: unknown }[] };
  const prefix = OfflineStore.recordKey(entity, '');
  const keys = (await store.keys('records')).filter(k => k.startsWith(prefix)).sort();
  const rows: Record<string, unknown>[] = [];
  for (const k of keys) {
    const r = await store.get<StoredRecord>('records', k);
    if (!r) continue;
    const flat = { ...((r['data'] as Record<string, unknown>) ?? {}), ...r };
    const keep = (q.filters ?? []).every(f => (f.op ?? 'eq') !== 'eq' || String(flat[f.field] ?? '') === String(f.value ?? ''));
    if (keep) rows.push(flat);
  }
  const pageSize = Math.max(1, Math.min(200, q.page_size ?? 50));
  const page = Math.max(1, q.page ?? 1);
  const records = rows.slice((page - 1) * pageSize, page * pageSize);
  return {
    metadata: { query_id: '', view_id: null, record_no: null, entity_logical_name: entity, can_edit_query: false, view_kind: null, view_metadata: null },
    data: { columns: [], records, total: rows.length, page, page_size: pageSize, total_pages: Math.ceil(rows.length / pageSize), offline: true },
  };
}
