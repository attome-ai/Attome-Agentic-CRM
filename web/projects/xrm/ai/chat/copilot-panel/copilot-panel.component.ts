import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, Injector, OnInit, afterNextRender,
  computed, inject, output, signal, viewChild,
} from '@angular/core';
import { takeUntilDestroyed, toSignal } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { NavigationEnd, Router } from '@angular/router';
import { Observable, filter, map, of, switchMap } from 'rxjs';
import { TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { ChatMessageComponent } from '../chat-message/chat-message.component';
import { ConfirmCardComponent } from '../confirm-card/confirm-card.component';
import type { ConfirmCardResult } from '../confirm-card/confirm-card.component';
import { recordContextFromUrl } from '../record-context';
import { ChatService } from '../services/chat.service';
import type {
  AgentOption, ChatMode, ConversationDetail, MessagePage, MessageView, RiskCeiling, ToolCallPage, ToolCallView, Vote,
} from '../services/chat.service';
import { CHAT_EVENT_SOURCE, ChatStream, DeltaBuffer } from '../services/chat-stream';
import type { StreamDelta, StreamEvent } from '../services/chat-stream';

type DockMode = 'docked' | 'floating';
const DOCK_KEY = 'xrm.ai.copilot.dock';

/**
 * The copilot panel (C7, C11 B4): one conversation with an `ai_agent`, over
 * the C4 chat API and the C10 stream, with no permission logic of its own.
 *
 * **Live, from the stream.** While a turn runs, the panel follows
 * `GET …/stream`: each durable event (a tool call starting or finishing, an
 * approval, the answer) refreshes the transcript and the tool-call list, so
 * the user watches the assistant work instead of a spinner; `message.delta`
 * frames show the answer forming, as provisional text the ledger's answer then
 * replaces (row A-79). A dropped connection resumes from the last durable
 * event on its own (the browser's `Last-Event-ID`). **Stop** ends the running
 * turn; what already ran is kept.
 *
 * What it relies on the server for, and never second-guesses:
 * - who may start a chat, read a conversation or confirm a proposal (I-20);
 * - what the assistant may do: every action goes through the gate;
 * - citations: rendered from `citations[]` only (row A-56).
 *
 * The record the user is viewing is sent as `context` — a navigation hint the
 * server stores in the message and never treats as authorization (I-19, A-66).
 * The user can switch that off per message.
 */
@Component({
  selector: 'attome-ai-copilot-panel',
  standalone: true,
  imports: [FormsModule, TranslatePipe, ChatMessageComponent, ConfirmCardComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./copilot-panel.component.css'],
  templateUrl: './copilot-panel.component.html',
  host: {
    '[class.copilot--docked]': "dock() === 'docked'",
    '[class.copilot--floating]': "dock() === 'floating'",
    '(keydown.escape)': 'close()',
  },
})
export class CopilotPanelComponent implements OnInit {
  private readonly chat = inject(ChatService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);
  private readonly eventSource = inject(CHAT_EVENT_SOURCE);

  readonly closed = output<void>();
  private readonly composer = viewChild<ElementRef<HTMLTextAreaElement>>('composer');
  private readonly injector = inject(Injector);

  readonly agents = signal<AgentOption[]>([]);
  readonly agentsLoaded = signal(false);
  readonly selectedAgentId = signal('');
  readonly riskCeiling = signal<RiskCeiling>('reversible');
  readonly mode = signal<ChatMode>('');
  readonly conversation = signal<ConversationDetail | null>(null);
  readonly messages = signal<MessageView[]>([]);
  readonly toolCalls = signal<ToolCallView[]>([]);
  readonly draft = signal('');
  readonly busy = signal(false);
  /** An i18n key, or a server message when `errorText` is set. */
  readonly errorKey = signal<string | null>(null);
  readonly errorText = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly shareContext = signal(true);
  readonly dock = signal<DockMode>(readDock());
  /** Client-side wall clock per turn — what the user waited, not a server metric. */
  private readonly latency = signal<Record<string, number>>({});
  /** The turn the server is running now, as the stream reports it. */
  readonly runningTurnId = signal<string | null>(null);
  /** The running turn's provisional text (row A-79): replaced by its answer. */
  readonly streamingText = signal('');
  readonly stopping = signal(false);
  /** Set by Stop; the composer gets focus back when the turn ends. */
  private refocusComposer = false;
  private stream: ChatStream | null = null;
  private readonly deltas = new DeltaBuffer();
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;

  private readonly url = toSignal(
    this.router.events.pipe(
      filter((e): e is NavigationEnd => e instanceof NavigationEnd),
      map((e) => e.urlAfterRedirects),
    ),
    { initialValue: this.router.url },
  );
  /** Navigation state only — see `recordContextFromUrl`. */
  readonly context = computed(() => recordContextFromUrl(this.url()));

  readonly proposals = computed(() => this.toolCalls().filter((c) => c.status === 'proposed'));
  readonly awaitingApproval = computed(() =>
    this.toolCalls().filter((c) => c.status === 'approval_pending'),
  );
  readonly callsByTurn = computed(() => {
    const byTurn = new Map<string, ToolCallView[]>();
    for (const call of this.toolCalls()) {
      byTurn.set(call.turn_id, [...(byTurn.get(call.turn_id) ?? []), call]);
    }
    return byTurn;
  });
  /** The running turn's tool calls, shown while it works. */
  readonly runningCalls = computed(() => {
    const turn = this.runningTurnId();
    return turn ? (this.callsByTurn().get(turn) ?? []) : [];
  });
  readonly canStop = computed(() => this.busy() && !!this.runningTurnId() && !this.stopping());
  readonly canSend = computed(
    () => !this.busy() && this.draft().trim().length > 0 && (!!this.conversation() || !!this.selectedAgentId()),
  );

  /** B10-T3: a question handed over (from the command palette) to send once an agent is chosen. */
  private pendingAsk = false;

  /**
   * B10-T3: puts `text` in the composer and sends it, now or as soon as the
   * agent list has chosen an agent; with several agents to pick from it waits
   * in the composer for the person.
   */
  ask(text: string): void {
    this.draft.set(text);
    if (this.canSend()) {
      this.send();
    } else {
      this.pendingAsk = true;
    }
  }

  ngOnInit(): void {
    this.destroyRef.onDestroy(() => {
      this.closeStream();
      if (this.refreshTimer) clearTimeout(this.refreshTimer);
    });
    this.chat
      .listAgents()
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (agents) => {
          this.agents.set(agents);
          if (agents.length === 1) this.selectedAgentId.set(agents[0].id);
          this.agentsLoaded.set(true);
          if (this.pendingAsk && this.canSend()) {
            this.pendingAsk = false;
            this.send();
          }
        },
        error: () => this.agentsLoaded.set(true),
      });
    queueMicrotask(() => this.composer()?.nativeElement.focus());
  }

  latencyFor(message: MessageView): number | undefined {
    return this.latency()[message.turn_id];
  }

  /** The newest request, when the newest answer completed: what "do this every time" repeats. */
  readonly repeatableTask = computed(() => {
    const all = this.messages();
    const last = all[all.length - 1];
    if (!last || last.role !== 'assistant' || last.terminal_state !== 'completed' || this.busy()) return null;
    const request = [...all].reverse().find((m) => m.role === 'user');
    return request && request.content.trim() ? request.content : null;
  });
  readonly flowSaving = signal(false);

  /** Saves the newest request as a workflow draft (N1-T3). */
  repeatAsFlow(): void {
    const task = this.repeatableTask();
    const agent = this.selectedAgentId();
    if (!task || !agent || this.flowSaving()) return;
    this.flowSaving.set(true);
    this.chat.createFlowDraft(agent, task).subscribe({
      next: () => {
        this.flowSaving.set(false);
        this.notice.set('aiChat.flow.created');
      },
      error: (e: ApiError) => {
        this.flowSaving.set(false);
        this.errorText.set(e.message);
      },
    });
  }

  isTurnFinal(message: MessageView): boolean {
    return message.role === 'assistant' && message.terminal_state != null;
  }

  /**
   * Whether a transcript row is shown. An assistant message that only asked
   * for tools (the ledger records it so the model can replay its own calls)
   * has no text for a person to read: the steps list shows what it asked.
   */
  isShown(message: MessageView): boolean {
    return message.role !== 'assistant' || this.isTurnFinal(message) || message.content.trim() !== '';
  }

  onComposerKeydown(event: KeyboardEvent): void {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.send();
    }
  }

  send(): void {
    const text = this.draft().trim();
    if (!this.canSend()) return;
    this.busy.set(true);
    this.clearMessages();
    const context = this.shareContext() ? this.context() : null;
    const started = performance.now();

    const conversation$ = this.conversation()
      ? of(this.conversation() as ConversationDetail)
      : this.chat.start(this.selectedAgentId(), this.riskCeiling(), this.mode());

    conversation$
      .pipe(
        switchMap((detail) => {
          this.conversation.set(detail);
          this.openStream(detail.conversation.id);
          return this.chat.send(detail.conversation.id, text, context);
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({
        next: (turn) => {
          const ms = Math.round(performance.now() - started);
          this.latency.update((all) => ({ ...all, [turn.turn_id]: ms }));
          this.draft.set('');
          this.endRunningTurn(turn.turn_id);
          this.busy.set(false);
          this.restoreFocusAfterStop();
          this.refresh();
        },
        error: (err: ApiError) => {
          this.endRunningTurn(this.runningTurnId());
          this.busy.set(false);
          this.restoreFocusAfterStop();
          this.showError(err);
          if (this.conversation()) this.refresh();
        },
      });
  }

  onCardResolved(result: ConfirmCardResult): void {
    if (result.kind === 'approval_requested') this.notice.set('aiChat.approval.requested');
    else if (result.kind === 'executed') this.notice.set('aiChat.confirm.executed');
    else if (result.kind === 'rejected') this.notice.set('aiChat.confirm.rejected');
    this.refresh();
  }

  /** Stop (C11 B4): the running turn ends at its next boundary. */
  stop(): void {
    const conversation = this.conversation()?.conversation.id;
    const turn = this.runningTurnId();
    if (!conversation || !turn || this.stopping()) return;
    this.stopping.set(true);
    this.refocusComposer = true;
    this.chat
      .cancel(conversation, turn)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        error: (err: ApiError) => {
          this.stopping.set(false);
          this.showError(err);
        },
      });
  }

  /** A thumbs vote on one answer; the recorded vote is what the button shows. */
  onVote(message: MessageView, vote: Vote): void {
    const conversation = this.conversation()?.conversation.id;
    if (!conversation) return;
    this.chat
      .feedback(conversation, message.id, vote)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (recorded) =>
          this.messages.update((all) =>
            all.map((m) => (m.id === recorded.message_id ? { ...m, feedback: recorded.vote } : m)),
          ),
        error: (err: ApiError) => this.showError(err),
      });
  }

  /** A durable event: a turn began or ended, or the transcript changed. */
  onStreamEvent(event: StreamEvent): void {
    const turn = event.turn_id;
    if (event.type === 'turn.started' && turn) {
      this.runningTurnId.set(turn);
    }
    // The step that streamed the current text called a tool: that text is
    // superseded, and the next step's streams from empty.
    if ((event.type === 'tool.call.proposed' || event.type === 'tool.call.started') && turn) {
      this.deltas.restart(turn);
      if (turn === this.runningTurnId()) this.streamingText.set('');
    }
    if ((event.type === 'message.completed' || event.type === 'turn.completed') && turn) {
      this.deltas.finish(turn);
      if (turn === this.runningTurnId()) this.streamingText.set('');
    }
    if (event.type === 'turn.completed' && turn) this.endRunningTurn(turn);
    this.scheduleRefresh();
  }

  /** Provisional text for a running turn. A delta can outrun `turn.started`. */
  onDelta(delta: StreamDelta): void {
    this.deltas.add(delta.turn_id, delta.text);
    const text = this.deltas.get(delta.turn_id);
    if (!text) return; // the turn already has its answer
    if (!this.runningTurnId()) this.runningTurnId.set(delta.turn_id);
    if (delta.turn_id === this.runningTurnId()) this.streamingText.set(text);
  }

  newConversation(): void {
    this.closeStream();
    const current = this.conversation();
    this.conversation.set(null);
    this.messages.set([]);
    this.toolCalls.set([]);
    this.latency.set({});
    this.clearMessages();
    if (current) {
      this.chat.end(current.conversation.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        error: () => undefined,
      });
    }
  }

  toggleDock(): void {
    const next: DockMode = this.dock() === 'docked' ? 'floating' : 'docked';
    this.dock.set(next);
    writeDock(next);
  }

  close(): void {
    this.closed.emit();
  }

  /** Reloads the newest page of the transcript and of the tool calls. */
  refresh(): void {
    const id = this.conversation()?.conversation.id;
    if (!id) return;
    this.chat
      .messages(id)
      .pipe(
        switchMap((page) => lastPageOf(page, (p) => this.chat.messages(id, p))),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({ next: (page) => this.messages.set(page.items), error: (e: ApiError) => this.showError(e) });
    this.chat
      .toolCalls(id)
      .pipe(
        switchMap((page) => lastPageOf(page, (p) => this.chat.toolCalls(id, p))),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe({ next: (page) => this.toolCalls.set(page.items), error: (e: ApiError) => this.showError(e) });
  }

  private openStream(conversationId: string): void {
    if (this.stream) return;
    this.stream = new ChatStream(
      this.chat.streamUrl(conversationId),
      {
        event: (e) => this.onStreamEvent(e),
        delta: (d) => this.onDelta(d),
        // The next send reopens it; until then the answer still arrives with
        // the send's own response, only without live steps or Stop.
        closed: () => {
          this.stream = null;
        },
      },
      this.eventSource,
    );
    this.stream.open();
  }

  private closeStream(): void {
    this.stream?.close();
    this.stream = null;
    this.runningTurnId.set(null);
    this.streamingText.set('');
    this.stopping.set(false);
  }

  /**
   * Stop leaves focus on a button that disappears when the turn ends; the
   * composer takes it back once it is enabled again.
   */
  private restoreFocusAfterStop(): void {
    if (!this.refocusComposer) return;
    this.refocusComposer = false;
    // `ngModel` applies `[disabled]` in a microtask after the render, so the
    // textarea is still disabled when the render hook runs; focus a task later.
    afterNextRender(() => setTimeout(() => this.composer()?.nativeElement.focus()), {
      injector: this.injector,
    });
  }

  private endRunningTurn(turn: string | null): void {
    if (turn) this.deltas.finish(turn);
    if (!turn || turn === this.runningTurnId()) {
      this.runningTurnId.set(null);
      this.streamingText.set('');
      this.stopping.set(false);
    }
  }

  /** Coalesces a burst of stream events into one reload. */
  private scheduleRefresh(): void {
    if (this.refreshTimer) return;
    this.refreshTimer = setTimeout(() => {
      this.refreshTimer = null;
      this.refresh();
    }, 150);
  }

  private clearMessages(): void {
    this.errorKey.set(null);
    this.errorText.set(null);
    this.notice.set(null);
  }

  private showError(err: ApiError): void {
    switch (err.status) {
      case 403:
        this.errorKey.set('aiChat.error.notAllowed');
        return;
      case 404:
        this.errorKey.set('aiChat.error.notFound');
        return;
      case 429:
        this.errorKey.set('aiChat.error.rateLimited');
        return;
      case 503:
        this.errorKey.set('aiChat.error.unavailable');
        return;
      default:
        this.errorText.set(err.message);
    }
  }
}

/** The newest page when there is more than one; the page itself otherwise. */
function lastPageOf<P extends MessagePage | ToolCallPage>(
  first: P,
  fetch: (page: number) => Observable<P>,
): Observable<P> {
  const last = ChatService.lastPage(first.total);
  return last > 1 ? fetch(last) : of(first);
}

function readDock(): DockMode {
  try {
    return localStorage.getItem(DOCK_KEY) === 'floating' ? 'floating' : 'docked';
  } catch {
    return 'docked';
  }
}

function writeDock(mode: DockMode): void {
  try {
    localStorage.setItem(DOCK_KEY, mode);
  } catch {
    // Storage unavailable: the choice lasts for this page only.
  }
}
