import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe, type Page } from '@attome/base';

/** `deferred::DeferredAction`. */
export interface DeferredAction {
  id:               string;
  action_id:        string;
  initiator:        'user' | 'agent';
  agent_session_id: string | null;
  acting_user_id:   string;
  /** `null` while staged for review. */
  run_at:           string | null;
  status:           string;
  reason:           string | null;
  approval_id:      string | null;
  created_at:       string;
}

/**
 * Pending actions (roadmap AH8, V2-D693): actions held for their undo
 * window — an agent's at `act_with_undo`, or any the person asked to hold —
 * with Cancel while they wait, and how the recent ones ended. Logical CSS
 * only.
 */
@Component({
  selector:        'xrm-ai-pending-actions',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [LocalDatePipe, TranslatePipe],
  templateUrl:     './pending-actions.component.html',
  styleUrls:       ['./autonomy.component.css'],
})
export class AiPendingActionsComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly actions = signal<DeferredAction[]>([]);
  readonly error   = signal<string | null>(null);
  readonly busy    = signal<string | null>(null);

  /** Staged actions, grouped by the agent session that staged them (V2-D702). */
  readonly reviewGroups = computed(() => {
    const groups = new Map<string, DeferredAction[]>();
    for (const a of this.actions()) {
      if (a.status !== 'staged' || !a.agent_session_id) continue;
      groups.set(a.agent_session_id, [...(groups.get(a.agent_session_id) ?? []), a]);
    }
    return [...groups].map(([session, items]) => ({ session, items }));
  });
  /** Everything not waiting for review. */
  readonly others = computed(() => this.actions().filter(a => a.status !== 'staged'));

  ngOnInit(): void {
    this.load();
  }

  /** Applies (runs) or discards staged actions: one, or a whole session's. */
  decide(apply: boolean, scope: { agent_session_id: string } | { ids: string[] }, busyKey: string): void {
    this.busy.set(busyKey);
    this.error.set(null);
    this.api.post<unknown>(`/api/v1/ai/deferred-actions/${apply ? 'apply' : 'discard'}`, scope).subscribe({
      next: () => { this.busy.set(null); this.load(); },
      error: (e: ApiError) => { this.busy.set(null); this.error.set(e.message); this.load(); },
    });
  }

  load(): void {
    this.api.get<Page<DeferredAction>>('/api/v1/ai/deferred-actions').subscribe({
      next: page => this.actions.set(page.items ?? []),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  cancel(action: DeferredAction): void {
    this.busy.set(action.id);
    this.error.set(null);
    this.api.post<DeferredAction>(`/api/v1/ai/deferred-actions/${encodeURIComponent(action.id)}/cancel`, {}).subscribe({
      next: () => { this.busy.set(null); this.load(); },
      error: (e: ApiError) => { this.busy.set(null); this.error.set(e.message); this.load(); },
    });
  }
}
