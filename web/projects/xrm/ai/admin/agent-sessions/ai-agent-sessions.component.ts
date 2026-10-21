import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { switchMap, takeWhile, timer } from 'rxjs';
import { LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { AiActionsService } from '../../services/ai-actions.service';
import type { ActionOutcome } from '../../services/ai-actions.service';
import { AdminAiService } from '../../services/admin-ai.service';
import type {
  AgentChildSession, AgentTraceStep, UndoRun, UndoStep,
} from '../../services/admin-ai.service';
import { AiRuntimeSwitchComponent } from '../runtime-switch/ai-runtime-switch.component';
import { AiBotAnalyticsComponent } from '../bot-analytics/ai-bot-analytics.component';
import type {
  AgentSessionPackRef, AgentSessionStatusFilter, AgentSessionSummary,
} from '../../services/admin-ai.service';

/** How a session's snapshotted allow-list reads, without ever collapsing null and []. */
type GrantState = 'unrestricted' | 'nothing' | 'listed' | 'unreadable';

/**
 * Live agent sessions — the supervisor screen over
 * `GET /api/v1/admin/agents/sessions` (C6, D-460).
 *
 * **This screen exists because a policy edit does not reach a running
 * session.** A session snapshots its ceiling and its grants at start (D-505
 * §4) and keeps them: that is correct, and it means the only way to remove a
 * capability from a session that is *right now* running is to pause or kill
 * it here. The notice at the top of the template says exactly that, because an
 * administrator who believes they revoked a capability and did not is a
 * security incident.
 *
 * The read and the three actions are all gated on the *same* privilege,
 * `ai_agent.supervise`, so a viewer who can see this page can act on it.
 * Nothing here is an authorization mechanism of its own: the three buttons
 * invoke registered actions through the ordinary
 * `POST /api/v1/actions/{id}/invoke` route, and the server's gate decides.
 */
@Component({
  selector: 'attome-ai-agent-sessions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe, AiRuntimeSwitchComponent, AiBotAnalyticsComponent],
  styleUrls: ['../../../styles/xrm-form.css', './ai-agent-sessions.component.css'],
  templateUrl: './ai-agent-sessions.component.html',
})
export class AiAgentSessionsComponent implements OnInit {
  private readonly adminAi = inject(AdminAiService);
  private readonly actions = inject(AiActionsService);
  private readonly viewDestroyRef = inject(DestroyRef);

  readonly sessions = signal<AgentSessionSummary[]>([]);
  readonly total = signal(0);
  /** One-based (D-347): the first page is 1. */
  readonly page = signal(1);
  readonly pageSize = 50;
  readonly status = signal<AgentSessionStatusFilter>('active');
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  /** Set on a 403 — the operator lacks ai_agent.supervise. */
  readonly forbidden = signal(false);
  /** The session a supervisor action is in flight for, if any. */
  readonly busyId = signal<string | null>(null);
  /** The session whose kill is waiting for its explicit second confirmation. */
  readonly killConfirmId = signal<string | null>(null);
  /**
   * An optional reason, sent with the next pause / resume / kill. One field for
   * the whole screen rather than one per row: the reason is optional and the
   * rows carry enough already.
   */
  readonly reason = signal('');
  /** The last action result, announced through a live region. */
  readonly outcome = signal<string | null>(null);
  /** N29-T2: the session whose steps are shown, and its steps. */
  readonly traceFor = signal<string | null>(null);
  readonly trace = signal<AgentTraceStep[]>([]);
  /** The sessions the traced session delegated to (N29-T3). */
  readonly children = signal<AgentChildSession[]>([]);
  /** A delegated session's steps, by its id, once opened. */
  readonly childTrace = signal<Record<string, AgentTraceStep[]>>({});

  /** AH1-T6: the session whose undo is previewed, its plan and its run. */
  readonly undoFor = signal<string | null>(null);
  readonly undoSteps = signal<UndoStep[]>([]);
  readonly undoRun = signal<UndoRun | null>(null);
  readonly undoBusy = signal(false);
  readonly undoError = signal<string | null>(null);
  /** The plan in three groups: what will be put back, what a person changed, what cannot be undone. */
  readonly undoRestores = computed(() =>
    this.undoSteps().filter(s => s.step === 'revert_fields' || s.step === 'soft_delete' || s.step === 'restore'));
  readonly undoSkipped = computed(() => this.undoSteps().filter(s => s.step === 'skip'));
  readonly undoImpossible = computed(() => this.undoSteps().filter(s => s.step === 'not_undoable'));

  readonly totalPages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));

  readonly statusFilters: { value: AgentSessionStatusFilter; label: string }[] = [
    { value: 'active', label: 'Active' },
    { value: 'paused', label: 'Paused' },
    { value: 'revoked', label: 'Revoked' },
    { value: 'ended', label: 'Ended' },
    { value: 'all', label: 'All statuses' },
  ];

  ngOnInit(): void {
    this.load();
  }

  /** Shows a session's steps, or hides them when they are already shown. */
  toggleTrace(session: AgentSessionSummary): void {
    if (this.traceFor() === session.id) {
      this.traceFor.set(null);
      this.trace.set([]);
      this.children.set([]);
      this.childTrace.set({});
      return;
    }
    this.traceFor.set(session.id);
    this.trace.set([]);
    this.children.set([]);
    this.childTrace.set({});
    this.adminAi
      .sessionChildren(session.id)
      .pipe(takeUntilDestroyed(this.viewDestroyRef))
      .subscribe({
        next: (page) => this.children.set(page.items ?? []),
        error: () => this.children.set([]),
      });
    this.adminAi
      .sessionTrace(session.id)
      .pipe(takeUntilDestroyed(this.viewDestroyRef))
      .subscribe({
        next: (page) => this.trace.set(page.items ?? []),
        error: (e: ApiError) => this.error.set(e.message),
      });
  }

  /** AH1-T6: previews undoing a session, or closes the preview. */
  previewUndo(session: AgentSessionSummary): void {
    if (this.undoFor() === session.id) {
      this.cancelUndo();
      return;
    }
    this.undoFor.set(session.id);
    this.undoSteps.set([]);
    this.undoRun.set(null);
    this.undoError.set(null);
    this.undoBusy.set(true);
    this.adminAi
      .undoPreview(session.id)
      .pipe(takeUntilDestroyed(this.viewDestroyRef))
      .subscribe({
        next: (page) => { this.undoSteps.set(page.items ?? []); this.undoBusy.set(false); },
        error: (e: ApiError) => { this.undoBusy.set(false); this.undoError.set(e.message); },
      });
  }

  cancelUndo(): void {
    this.undoFor.set(null);
    this.undoSteps.set([]);
    this.undoRun.set(null);
    this.undoError.set(null);
  }

  /** Starts the previewed undo, then follows its run every two seconds until it ends. */
  confirmUndo(): void {
    const sessionId = this.undoFor();
    if (!sessionId || this.undoBusy()) return;
    this.undoBusy.set(true);
    this.undoError.set(null);
    this.adminAi
      .startUndo(sessionId)
      .pipe(
        switchMap(({ undo_run_id }) => timer(0, 2000).pipe(switchMap(() => this.adminAi.undoRun(undo_run_id)))),
        takeWhile(run => run.status === 'planned' || run.status === 'running', true),
        takeUntilDestroyed(this.viewDestroyRef),
      )
      .subscribe({
        next: (run) => {
          this.undoRun.set(run);
          if (run.status === 'done' || run.status === 'failed') this.undoBusy.set(false);
        },
        error: (e: ApiError) => { this.undoBusy.set(false); this.undoError.set(e.message); },
      });
  }

  /** The undo run's count of one outcome. */
  undoCount(outcome: string): number {
    return this.undoRun()?.summary?.[outcome] ?? 0;
  }

  /** Shows a delegated session's steps, or hides them. */
  toggleChild(id: string): void {
    const open = { ...this.childTrace() };
    if (open[id]) {
      this.childTrace.set(Object.fromEntries(Object.entries(open).filter(([key]) => key !== id)));
      return;
    }
    this.adminAi
      .sessionTrace(id)
      .pipe(takeUntilDestroyed(this.viewDestroyRef))
      .subscribe({
        next: (page) => this.childTrace.set({ ...this.childTrace(), [id]: page.items ?? [] }),
        error: (e: ApiError) => this.error.set(e.message),
      });
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.adminAi
      .listAgentSessions(this.status(), this.page(), this.pageSize)
      .pipe(takeUntilDestroyed(this.viewDestroyRef))
      .subscribe({
        next: (reply) => {
          this.sessions.set(reply.items ?? []);
          this.total.set(reply.total);
          // Follow the page the server says it served: a handler that clamps an
          // out-of-range page reports the clamped one, and following it keeps
          // the pager (and the next/previous arithmetic) aligned.
          this.page.set(reply.page);
          this.loading.set(false);
        },
        error: (e: ApiError) => {
          this.loading.set(false);
          if (e?.status === 403) {
            this.forbidden.set(true);
            this.sessions.set([]);
            this.total.set(0);
            return;
          }
          this.error.set(e?.message ?? 'Could not read live sessions.');
        },
      });
  }

  changeStatus(value: AgentSessionStatusFilter): void {
    this.status.set(value);
    // Back to the first page: page 4 of the previous filter has nothing to do
    // with page 4 of this one.
    this.page.set(1);
    this.killConfirmId.set(null);
    this.outcome.set(null);
    this.load();
  }

  previousPage(): void {
    if (this.page() <= 1 || this.loading()) return;
    this.page.update((p) => p - 1);
    this.load();
  }

  nextPage(): void {
    if (this.page() >= this.totalPages() || this.loading()) return;
    this.page.update((p) => p + 1);
    this.load();
  }

  // ── Rendering a session's grant, honestly ──────────────────────────────────

  /**
   * `null` is "not narrowed by a list"; `[]` is "granted nothing". The two
   * are never collapsed here (I-16) — no `?? []`, no truthiness test, and no
   * shared "has grants" helper that would quietly turn one into the other.
   * `'unreadable'` exists for a value that is neither, and is rendered as
   * itself rather than as either meaning.
   */
  grantState(session: AgentSessionSummary): GrantState {
    const value: unknown = session.allowed_action_ids;
    if (value === null || value === undefined) return 'unrestricted';
    if (!Array.isArray(value)) return 'unreadable';
    return value.length === 0 ? 'nothing' : 'listed';
  }

  /** Only called for the `'listed'` state. */
  grantIds(session: AgentSessionSummary): string[] {
    const value: unknown = session.allowed_action_ids;
    return Array.isArray(value) ? value.map(String) : [];
  }

  /** Pack provenance: `null` reads "—"; an empty array is said in words, not skipped. */
  packRefs(session: AgentSessionSummary): AgentSessionPackRef[] | null {
    const value: unknown = session.capability_pack_refs;
    if (value === null || value === undefined) return null;
    return Array.isArray(value) ? (value as AgentSessionPackRef[]) : null;
  }

  /**
   * The catalog key naming a stored or configured retrieval mode. Anything
   * other than the two modes is shown as unrecognised, never as either one.
   */
  modeKey(mode: string | null | undefined): string {
    switch (mode) {
      case 'tool_invoked':
        return 'agentSessions.modeToolInvoked';
      case 'pre_retrieved':
        return 'agentSessions.modePreRetrieved';
      default:
        return 'agentSessions.modeUnrecognised';
    }
  }

  /** The definition now holds a different mode than the session uses. */
  modeDiffers(session: AgentSessionSummary): boolean {
    const configured = session.agent_retrieval_mode ?? null;
    return configured !== null && configured !== session.retrieval_mode;
  }

  shortId(id: string): string {
    return id.slice(0, 8);
  }

  // ── Supervisor actions ─────────────────────────────────────────────────────

  canPause(session: AgentSessionSummary): boolean {
    return session.status === 'active';
  }

  canResume(session: AgentSessionSummary): boolean {
    return session.status === 'paused';
  }

  canKill(session: AgentSessionSummary): boolean {
    return session.status === 'active' || session.status === 'paused';
  }

  /** Kill is two-step: this only opens the confirmation for that one row. */
  askKill(session: AgentSessionSummary): void {
    this.killConfirmId.set(session.id);
    this.outcome.set(null);
  }

  cancelKill(): void {
    this.killConfirmId.set(null);
  }

  confirmKill(session: AgentSessionSummary): void {
    this.run(session, 'agent.kill');
  }

  pause(session: AgentSessionSummary): void {
    this.run(session, 'agent.pause');
  }

  resume(session: AgentSessionSummary): void {
    this.run(session, 'agent.resume');
  }

  /**
   * Invokes one of the three registered supervisor actions through the ordinary
   * action route. `agent.pause` / `agent.resume` / `agent.kill` are
   * `Consequential` in the catalogue, so the gate decides what happens: a human
   * supervisor holding `ai_agent.supervise` executes immediately
   * (`'completed'`), while `'confirmation_required'` and
   * `'approval_required'` mean the call stopped short. Those two are NOT errors
   * and must not be rendered as if the session had stopped — nothing happened,
   * and this screen says so.
   */
  private run(
    session: AgentSessionSummary,
    actionId: 'agent.pause' | 'agent.resume' | 'agent.kill',
  ): void {
    if (this.busyId()) return;
    this.busyId.set(session.id);
    this.outcome.set(null);

    const trimmed = this.reason().trim();
    const args = trimmed
      ? { session_id: session.id, reason: trimmed }
      : { session_id: session.id };

    this.actions
      .invoke(actionId, args)
      .pipe(takeUntilDestroyed(this.viewDestroyRef))
      .subscribe({
        next: (outcome) => {
          this.busyId.set(null);
          this.killConfirmId.set(null);
          this.outcome.set(this.describeOutcome(session, actionId, outcome));
          // Reload only after a completed action: the other two changed nothing,
          // and re-reading would suggest they had.
          if (outcome.status === 'completed') this.load();
        },
        error: (e: unknown) => {
          this.busyId.set(null);
          this.outcome.set(this.describeError(e));
        },
      });
  }

  private describeOutcome(
    session: AgentSessionSummary,
    actionId: string,
    outcome: ActionOutcome,
  ): string {
    const id = this.shortId(session.id);
    if (outcome.status === 'completed') {
      switch (actionId) {
        case 'agent.pause':
          return `Session ${id} paused. It stays paused until it is resumed.`;
        case 'agent.resume':
          return `Session ${id} resumed.`;
        default:
          return `Session ${id} killed. A killed session is not resumable — it must be started fresh.`;
      }
    }
    if (outcome.status === 'confirmation_required') {
      return `Nothing happened: the gate stopped short and asked for confirmation (${outcome.reason}). Session ${id} is unchanged.`;
    }
    return `Nothing happened: this action needs approval before it runs, so session ${id} is unchanged.`;
  }

  private describeError(err: unknown): string {
    const e = err as Partial<ApiError> | null;
    if (e?.status === 403) {
      return 'Your account does not hold ai_agent.supervise, which the session read and the three supervisor actions all require. Nothing was changed.';
    }
    return `${e?.message ?? 'The request failed'}. Nothing was changed.`;
  }
}
