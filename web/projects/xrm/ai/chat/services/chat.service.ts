import { Injectable, inject } from '@angular/core';
import { Observable, map, switchMap } from 'rxjs';
import { ATTOME_CONFIG, ApiService } from '@attome/base';
import type { ApiComponents } from '@attome/base';
import { flowDraft } from '../copilot-panel/copilot-components';

type Schemas = ApiComponents['schemas'];

/** The C4/C7 wire shapes, taken from the generated OpenAPI types — never hand-copied. */
export type ConversationDetail = Schemas['ConversationDetail'];
export type MessageView = Schemas['MessageView'];
export type MessagePage = Schemas['PaginatedResponse_MessageView'];
export type ToolCallView = Schemas['ToolCallView'];
export type ToolCallPage = Schemas['PaginatedResponse_ToolCallView'];
export type TurnResponse = Schemas['TurnResponse'];
export type PendingView = Schemas['PendingView'];
export type CitationView = Schemas['CitationView'];
export type Grounding = Schemas['Grounding'];
export type RecordContext = Schemas['RecordContext'];
export type ConfirmExecuted = Schemas['ConfirmExecuted'];
export type ConfirmApprovalRequested = Schemas['ConfirmApprovalRequested'];
export type FeedbackView = Schemas['FeedbackView'];
export type CancelTurnView = Schemas['CancelTurnView'];
/** A thumbs vote on a turn's answer. */
export type Vote = Schemas['FeedbackRequest']['vote'];
/** `200` ran it now; `202` requested four-eyes approval. Told apart by `outcome`. */
export type ConfirmResult = ConfirmExecuted | ConfirmApprovalRequested;

/**
 * What a conversation is for (N1-T1): `develop` builds (metadata tools and
 * reads; every change is a draft), `run` acts (everything but the metadata
 * edit tools). Empty: no narrowing.
 */
export type ChatMode = 'develop' | 'run' | '';

/** The session ceiling a conversation is started with. The agent policy still bounds it. */
export type RiskCeiling = 'read' | 'reversible' | 'consequential';

export interface AgentOption {
  id: string;
  name: string;
}

const BASE = '/api/v1/ai/conversations';
/** The largest page the conversation routes serve (`attome_types::MAX_PAGE_SIZE`). */
const PAGE_SIZE = 100;

/**
 * The chat HTTP API (C4) plus the C7 read projections — nothing else. Every
 * call is authorized by the server as the signed-in user; this service holds no
 * permission logic of its own (I-19, I-20).
 */
@Injectable({ providedIn: 'root' })
export class ChatService {
  private readonly api = inject(ApiService);
  private readonly config = inject(ATTOME_CONFIG);

  /**
   * The agent definitions the caller can read. There is no GET-list on the
   * generic entity API, so this goes through `query/execute`'s ad-hoc mode —
   * the playground's route to the same picklist.
   */
  listAgents(): Observable<AgentOption[]> {
    return this.api
      .post<{ data: { records: Record<string, unknown>[] } }>('/api/v1/query/execute', {
        entity: 'ai_agent',
        page_size: 100,
      })
      .pipe(
        map((resp) =>
          (resp.data?.records ?? []).map((r) => ({
            id: String(r['id']),
            name: String(r['name'] ?? r['id']),
          })),
        ),
      );
  }

  start(agentDefinitionId: string, riskCeiling: RiskCeiling, mode: ChatMode = ''): Observable<ConversationDetail> {
    const body: Schemas['StartConversationRequest'] = {
      agent_definition_id: agentDefinitionId,
      risk_ceiling: riskCeiling,
      ...(mode ? { mode } : {}),
    };
    return this.api.post<ConversationDetail>(BASE, body);
  }

  /**
   * Sends one message. `context` is the record the user is looking at — a
   * navigation hint the server stores as part of the message, never an
   * authorization input (I-19).
   */
  send(conversationId: string, text: string, context: RecordContext | null): Observable<TurnResponse> {
    const body: Schemas['SendChatMessageRequest'] = context ? { text, context } : { text };
    return this.api.post<TurnResponse>(`${BASE}/${conversationId}/messages`, body);
  }

  /**
   * Gives the agent a task to work through in the background (N7-T1). Returns
   * at once; the run's steps and end state arrive on the conversation's
   * stream like any turn's.
   */
  startRun(conversationId: string, task: string, maxSteps?: number): Observable<{ conversation_id: string; status: string }> {
    const body: { task: string; max_steps?: number } = maxSteps === undefined ? { task } : { task, max_steps: maxSteps };
    return this.api.post<{ conversation_id: string; status: string }>(`${BASE}/${conversationId}/runs`, body);
  }

  /** The newest page of the transcript, oldest first within it. */
  messages(conversationId: string, page = 1): Observable<MessagePage> {
    return this.api.get<MessagePage>(`${BASE}/${conversationId}/messages`, {
      page: String(page),
      page_size: String(PAGE_SIZE),
    });
  }

  toolCalls(conversationId: string, page = 1): Observable<ToolCallPage> {
    return this.api.get<ToolCallPage>(`${BASE}/${conversationId}/tool-calls`, {
      page: String(page),
      page_size: String(PAGE_SIZE),
    });
  }

  /**
   * Confirms a **server-persisted** proposal. Takes the tool-call id and the
   * hash the card displayed — and nothing else, by construction: the
   * arguments that run are the server's stored copy (I-13, row A-08).
   */
  confirm(conversationId: string, toolCallId: string, argumentsHash: string): Observable<ConfirmResult> {
    const body: Schemas['ConfirmToolCallRequest'] = { arguments_hash: argumentsHash };
    return this.api.post<ConfirmResult>(
      `${BASE}/${conversationId}/tool-calls/${encodeURIComponent(toolCallId)}/confirm`,
      body,
    );
  }

  reject(conversationId: string, toolCallId: string): Observable<void> {
    return this.api.delete(`${BASE}/${conversationId}/tool-calls/${encodeURIComponent(toolCallId)}`);
  }

  /**
   * The conversation's Server-Sent Events URL (C10-A). `after` is the last
   * durable ordinal already seen; the browser resumes from there on its own
   * after a dropped connection.
   */
  streamUrl(conversationId: string, after?: number): string {
    // Without `after`, the server starts from the browser's `Last-Event-ID`
    // (or the beginning), so an automatic reconnect resumes where it left
    // off. A fixed `after` in the URL would win over that header and replay
    // the whole log on every reconnect.
    const cursor = after === undefined ? '' : `?after=${after}`;
    return `${this.config.apiUrl}${BASE}/${conversationId}/stream${cursor}`;
  }

  /**
   * Stop (C11 B4): the turn ends at its next boundary. A tool call already
   * running completes; a proposal waiting for confirmation is untouched.
   */
  cancel(conversationId: string, turnId: string): Observable<CancelTurnView> {
    return this.api.post<CancelTurnView>(`${BASE}/${conversationId}/turns/${turnId}/cancel`, {});
  }

  /** The caller's thumbs vote on a turn's answer; a new vote replaces the old. */
  feedback(conversationId: string, messageId: string, vote: Vote): Observable<FeedbackView> {
    const body: Schemas['FeedbackRequest'] = { vote };
    return this.api.put<FeedbackView>(`${BASE}/${conversationId}/messages/${messageId}/feedback`, body);
  }

  end(conversationId: string): Observable<void> {
    return this.api.delete(`${BASE}/${conversationId}`);
  }

  /**
   * A record's current values, for a confirmation card's diff — an ordinary
   * read as the user through the generic entity API, so it is refused exactly
   * when the user may not read the record. Display only; never sent back.
   */
  currentRecord(entity: string, recordId: string): Observable<Record<string, unknown>> {
    return this.api
      .get<{ data: Record<string, unknown> }>(`/api/v1/${entity}/${recordId}`)
      .pipe(map((r) => r.data ?? {}));
  }

  /**
   * "Do this every time" (N1-T3): saves the request as an unpublished
   * workflow draft that runs the same agent on the same task. Returns the
   * new definition's id; a person schedules and publishes it.
   */
  createFlowDraft(agentDefinitionId: string, task: string): Observable<string> {
    const draft = flowDraft(agentDefinitionId, task, new Date());
    return this.api
      .post<Schemas['DefinitionDetail']>('/api/v1/workflow/definitions', {
        logicalname: draft.logicalname,
        name: draft.name,
      })
      .pipe(
        switchMap((definition) =>
          this.api
            .post<unknown>(`/api/v1/workflow/definitions/${encodeURIComponent(definition.id)}/versions`, {
              graph: draft.graph,
            })
            .pipe(map(() => definition.id)),
        ),
      );
  }

  /** Total pages of a transcript of `total` messages at this service's page size. */
  static lastPage(total: number): number {
    return Math.max(1, Math.ceil(total / PAGE_SIZE));
  }
}
