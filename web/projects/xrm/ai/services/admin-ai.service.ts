import { inject, Injectable } from '@angular/core';
import { map, Observable } from 'rxjs';
import { ApiService, type Page } from '@attome/base';
import type { ApiComponents } from '@attome/base';

/** C11 B5 — the runtime AI switch, as the admin route returns it (generated types). */
export type RuntimeSwitchView = ApiComponents['schemas']['RuntimeSwitchView'];
export type SurfaceSwitchView = ApiComponents['schemas']['SurfaceSwitchView'];
/** C10 B2b — the assistant's analytics report (generated types). */
export type BotAnalytics = ApiComponents['schemas']['BotAnalytics'];

/**
 * One row of `ai_capability_pack`, as the ad-hoc list path returns it.
 *
 * `action_ids` is a `text` column holding a JSON array of action ids (the
 * entity ships that way in `platform-bundles/attome-ai-capability-pack.json`),
 * so it is a string on the wire and goes through `parseJsonIdArray` here like
 * every other JSON-string id list.
 */
export interface CapabilityPackRow {
  id: string;
  name: string;
  description: string | null;
  action_ids: string | null;
}

/** One row of `knowledge_data_source`, read the same way. */
export interface KnowledgeSourceRow {
  id: string;
  name: string | null;
}

/** A pack reference snapshotted onto a session: its id and the version it held. */
export interface AgentSessionPackRef {
  id: string;
  row_version: number;
}

/** `session_admin::status_of` — derived from the session's timestamp columns. */
export type AgentSessionStatus = 'active' | 'paused' | 'revoked' | 'ended';

/** The filter's own union: the four statuses, plus "do not filter at all". */
export type AgentSessionStatusFilter = AgentSessionStatus | 'all';

/**
 * One row of `GET /api/v1/admin/agents/sessions`
 * (`session_admin::SessionSummary`) — a session's ceiling and grants as they
 * were **snapshotted at start**, not as the policy reads now.
 *
 * `allowed_action_ids` is `string[] | null` and the difference is load-bearing
 * (invariant I-16): `null` means the session is *not narrowed by a list* — the
 * ceiling and the other constraints are what bound it — while `[]` means it is
 * explicitly granted **nothing**. No consumer of this type may write `?? []`,
 * `|| []`, or `unwrap_or_default` for that field: collapsing the pair is
 * exactly the failure the invariant exists to prevent. A screen may only render
 * them differently, which is what the supervisor screen does.
 */
export interface AgentSessionSummary {
  id: string;
  owner_user_id: string;
  /** `'read' | 'reversible' | 'consequential'` — the snapshotted ceiling. */
  risk_ceiling: string;
  allowed_action_ids: string[] | null;
  /** Provenance only (D-556 §2) — never consulted for authorization. */
  capability_pack_refs: AgentSessionPackRef[] | null;
  surface: string;
  agent_definition_ref: string | null;
  started_at: string;
  status: AgentSessionStatus;
  tainted: boolean;
  /**
   * D-561 §5: the knowledge retrieval mode the session uses — stored when it
   * started (`tool_invoked` | `pre_retrieved`). Nothing changes it afterwards.
   */
  retrieval_mode: string;
  /**
   * The mode the session's agent definition holds now, for comparison only:
   * it reaches the next session, never this one. `unrecognised` for a value a
   * new session would refuse; `null` when there is no definition.
   */
  agent_retrieval_mode?: string | null;
}

/** The `{ data: { records } }` envelope `POST /api/v1/query/execute` answers an ad-hoc read in. */
interface QueryExecuteResponse {
  data?: { records?: Record<string, unknown>[] };
}

/**
 * Parses a JSON-string id array — the shape several text columns store: a
 * policy's `capability_pack_refs` and `knowledge_source_refs`, a pack's
 * `action_ids`, and (when Angular hands it back as text rather than a real
 * array) a multi-choice `allowed_action_ids`.
 *
 * **`null` means absent and is never turned into `[]`** (I-16): a NULL/blank
 * value, the literal text `null`, or anything that does not parse into an array
 * returns `null`. An empty array on the wire stays an empty array — "explicitly
 * nothing" — because the caller is the only place that knows which of the two
 * meanings applies to its own field.
 */
export function parseJsonIdArray(raw: unknown): string[] | null {
  // Angular gives back `null`, `undefined`, or — for a field whose schema type
  // is a multi-choice — a real array. All three arrive here.
  if (raw === null || raw === undefined) return null;
  if (Array.isArray(raw)) return raw.map(String);
  if (typeof raw !== 'string') return null;

  const text = raw.trim();
  // `''` is what an untouched text column reads as. It is "absent", not "[]":
  // nothing was ever selected, so there is no list to narrow by.
  if (text === '' || text === 'null') return null;
  try {
    const parsed: unknown = JSON.parse(text);
    return Array.isArray(parsed) ? parsed.map(String) : null;
  } catch {
    return null;
  }
}

/**
 * The reads behind the capability-administration screens: the capability-pack
 * and knowledge-source catalogues (both ordinary metadata entities, so both go
 * through the one `query/execute` ad-hoc list path every lookup uses) and the
 * supervisor's session read.
 *
 * **There is no write here, and no second authorization mechanism.** The forms
 * that use this edit metadata through the ordinary entity API
 * (`EngineFormBase.save()`), and the supervisor screen acts on a session only by
 * invoking the three registered actions (`agent.pause` / `agent.resume` /
 * `agent.kill`) through `AiActionsService.invoke` — the same route and the
 * same gate every other action goes through.
 */
@Injectable({ providedIn: 'root' })
export class AdminAiService {
  private readonly api = inject(ApiService);

  /** Every AI surface: configuration, runtime switch, and the two together (C11 B5). */
  runtimeSwitch(): Observable<RuntimeSwitchView> {
    return this.api.get<RuntimeSwitchView>('/api/v1/admin/ai/runtime-switch');
  }

  /**
   * Turns one AI surface off, or back on, without a restart. It can only
   * narrow: on restores what the configuration allows, never more.
   */
  setRuntimeSwitch(surface: string, enabled: boolean, reason: string | null): Observable<RuntimeSwitchView> {
    return this.api.put<RuntimeSwitchView>(
      `/api/v1/admin/ai/runtime-switch/${encodeURIComponent(surface)}`,
      { enabled, reason },
    );
  }

  /**
   * The assistant's analytics for `[from, to)` (C10 B2b): aggregates only,
   * administrators only. The same seven-day figures ship as metrics in
   * `platform-bundles/attome-ai-bot-analytics*.json`.
   */
  botAnalytics(from: string, to: string): Observable<BotAnalytics> {
    return this.api.get<BotAnalytics>('/api/v1/admin/ai/bot-analytics', { from, to });
  }

  /**
   * Every capability pack, for the policy form's reference list.
   *
   * `page_size: 200` mirrors the playground's ad-hoc read of `ai_agent`
   * (the query engine's own default page size). A deployment with more than
   * 200 packs needs a paged picker, not a bigger constant.
   */
  listCapabilityPacks(): Observable<CapabilityPackRow[]> {
    return this.api
      .post<QueryExecuteResponse>('/api/v1/query/execute', {
        entity: 'ai_capability_pack',
        page_size: 200,
      })
      .pipe(
        map((r) => (r.data?.records ?? []).map((row) => ({
          id: String(row['id']),
          name: String(row['name'] ?? row['id']),
          description: row['description'] === null || row['description'] === undefined
            ? null
            : String(row['description']),
          action_ids: row['action_ids'] === null || row['action_ids'] === undefined
            ? null
            : String(row['action_ids']),
        }))),
      );
  }

  /** Every knowledge data source, for the policy form's retrieval-scope list. */
  listKnowledgeSources(): Observable<KnowledgeSourceRow[]> {
    return this.api
      .post<QueryExecuteResponse>('/api/v1/query/execute', {
        entity: 'knowledge_data_source',
        page_size: 200,
      })
      .pipe(
        map((r) => (r.data?.records ?? []).map((row) => ({
          id: String(row['id']),
          // A source's display name is genuinely optional; the id is not, and
          // is a usable label when the name column is empty.
          name: row['name'] === null || row['name'] === undefined
            ? null
            : String(row['name']),
        }))),
      );
  }

  /**
   * One page of sessions, newest-first as the handler orders them.
   *
   * `page` is ONE-based (D-347): the first page is `page=1`. The `status`
   * param is left off entirely for `'all'` — the handler's own `None` is
   * "unfiltered", and an empty string would be a value its status parser has to
   * reject rather than "no filter".
   */
  listAgentSessions(
    status: AgentSessionStatusFilter,
    page: number,
    pageSize: number,
  ): Observable<Page<AgentSessionSummary>> {
    const params: Record<string, string> = {
      page: String(page),
      page_size: String(pageSize),
    };
    if (status !== 'all') params['status'] = status;
    return this.api.get<Page<AgentSessionSummary>>('/api/v1/admin/agents/sessions', params);
  }

  /** A session's steps, oldest first (`GET /api/v1/admin/agents/sessions/{id}/trace`, N29-T2). */
  sessionTrace(id: string): Observable<Page<AgentTraceStep>> {
    return this.api.get<Page<AgentTraceStep>>(`/api/v1/admin/agents/sessions/${encodeURIComponent(id)}/trace`);
  }
}

/** One step of a session's run (`session_admin::TraceStep`). */
export interface AgentTraceStep {
  id:             string;
  action_id:      string;
  outcome:        string;
  tool_call_id:   string | null;
  acting_user_id: string;
  created_at:     string;
}
