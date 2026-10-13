import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService } from '@attome/base';
import { AiActionsService } from '../services/ai-actions.service';

interface AgentOption {
  id: string;
  name: string;
}

interface Turn {
  role: 'user' | 'assistant' | 'error';
  text: string;
  modelId?: string;
  /**
   * Client-side wall clock from send to response — network, the server's
   * own work, and JSON parsing, same convention and same caveat
   * `search/lab`'s `Probe.ms` documents: it is what the user experienced,
   * not a server-side timing metric.
   */
  latencyMs?: number;
}

/**
 * The AI Playground — send one message to an `ai_agent` definition's
 * persona and see the reply, without creating a session.
 *
 * Runs as the logged-in caller against the `agent.playground_complete`
 * action (`crates/engine/attome-ai/src/actions/agent_playground.rs`) through the
 * ordinary `POST /api/v1/actions/{id}/invoke` surface every other action
 * uses — same "no bypass, no special path in" posture `search/lab` and the
 * MCP surface already follow. There is deliberately no multi-turn session
 * here: `crate::agent::start_session` (the real session/governance path) is
 * a separate surface with its own governance — it reads the D-503
 * persona/model-config schema (`primary_model_ref`, `policy_ref`,
 * `system_instructions`) and opens a revocable, budgeted session. The
 * playground deliberately opens none: each send is independent, and nothing
 * here persists beyond the visible transcript.
 */
@Component({
  selector: 'attome-ai-playground',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./ai-playground.component.css'],
  templateUrl: './ai-playground.component.html',
})
export class AiPlaygroundComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly actions = inject(AiActionsService);

  readonly agents = signal<AgentOption[]>([]);
  readonly agentsLoaded = signal(false);
  readonly selectedAgentId = signal<string>('');
  readonly message = signal('');
  readonly busy = signal(false);
  readonly turns = signal<Turn[]>([]);

  /** A few generic conversation starters — not agent-specific, just a faster way in. */
  readonly suggestedPrompts = [
    'Introduce yourself in two sentences.',
    'What can you help me with?',
    'Summarize your role in one paragraph.',
  ];

  readonly selectedAgentName = computed(
    () => this.agents().find((a) => a.id === this.selectedAgentId())?.name ?? '',
  );

  ngOnInit(): void {
    // The only route to a picklist: there is no GET-list on the generic
    // entity API (only POST create/upsert and /{id} — see
    // `attome_records::entity_crud`), so listing goes through the same
    // `query/execute` ad-hoc mode every lookup search uses.
    this.api
      .post<{ data: { records: Record<string, unknown>[] } }>('/api/v1/query/execute', {
        entity: 'ai_agent',
        page_size: 100,
      })
      .subscribe({
        next: (resp) => {
          this.agents.set(
            (resp.data?.records ?? []).map((r) => ({
              id: String(r['id']),
              name: String(r['name'] ?? r['id']),
            })),
          );
          this.agentsLoaded.set(true);
        },
        error: () => this.agentsLoaded.set(true),
      });
  }

  send(): void {
    const agentId = this.selectedAgentId();
    const text = this.message().trim();
    if (!agentId || !text || this.busy()) return;

    this.turns.update((all) => [...all, { role: 'user', text }]);
    this.message.set('');
    this.busy.set(true);
    // `performance.now()`, not `Date.now()`: monotonic, immune to a clock
    // adjustment landing mid-request and producing a negative duration —
    // same reasoning `search/lab`'s own timing uses.
    const started = performance.now();
    const elapsed = () => Math.round(performance.now() - started);

    this.actions.invoke('agent.playground_complete', { agent_id: agentId, message: text }).subscribe({
      next: (outcome) => {
        this.busy.set(false);
        if (outcome.status === 'completed') {
          const result = outcome.result as { reply?: string };
          this.turns.update((all) => [
            ...all,
            {
              role: 'assistant',
              text: result.reply ?? '(empty reply)',
              modelId: outcome.provenance?.model_id,
              latencyMs: elapsed(),
            },
          ]);
        } else if (outcome.status === 'confirmation_required') {
          this.turns.update((all) => [
            ...all,
            { role: 'error', text: `Needs confirmation: ${outcome.reason}`, latencyMs: elapsed() },
          ]);
        } else {
          this.turns.update((all) => [
            ...all,
            {
              role: 'error',
              text: 'This request requires approval before it can run.',
              latencyMs: elapsed(),
            },
          ]);
        }
      },
      error: (err: unknown) => {
        this.busy.set(false);
        this.turns.update((all) => [
          ...all,
          { role: 'error', text: this.describe(err), latencyMs: elapsed() },
        ]);
      },
    });
  }

  clear(): void {
    this.turns.set([]);
  }

  useSuggestion(prompt: string): void {
    this.message.set(prompt);
  }

  private describe(err: unknown): string {
    const e = err as { status?: number; error?: { message?: string }; message?: string };
    const status = e?.status ? `${e.status} ` : '';
    return `${status}${e?.error?.message ?? e?.message ?? 'request failed'}`;
  }
}
