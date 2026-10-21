import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe, type Page } from '@attome/base';

/** `autonomy::AutonomyLevel`, lowest first. */
export const AUTONOMY_LEVELS = ['suggest', 'ask_first', 'act_with_undo', 'act_and_report', 'automatic'] as const;
export type AutonomyLevel = (typeof AUTONOMY_LEVELS)[number];

/** `autonomy::AutonomyRow`. */
export interface AutonomyRow {
  id:                 string;
  level:              number;
  undo_seconds:       number;
  daily_limit:        number | null;
  money_cap_minor:    number | null;
  currency:           string | null;
  owned_records_only: boolean;
  hours_start:        number | null;
  hours_end:          number | null;
  time_zone:          string | null;
  row_version:        number;
}

/** `autonomy::AutonomyEntry`. */
export interface AutonomyEntry {
  action_id:     string;
  risk:          'Read' | 'Reversible' | 'Consequential';
  effect:        string;
  default_level: AutonomyLevel;
  level:         AutonomyLevel | null;
  locked:        boolean;
  row:           AutonomyRow | null;
}

/** Whether saving `level` lets a consequential action run without approval. */
export function raisesConsequential(entry: AutonomyEntry, level: AutonomyLevel): boolean {
  return entry.risk === 'Consequential' && AUTONOMY_LEVELS.indexOf(level) > AUTONOMY_LEVELS.indexOf('ask_first');
}

/**
 * An agent's autonomy levels (roadmap AH8, V2-D693): for each action the
 * agent may call, how much it may do on its own, with the undo window and
 * the daily limit. No level set keeps the built-in rule. Administrators
 * only (the API refuses others). Logical CSS only.
 */
@Component({
  selector:        'xrm-ai-agent-autonomy',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './agent-autonomy.component.html',
  styleUrls:       ['./autonomy.component.css'],
})
export class AiAgentAutonomyComponent {
  private readonly api = inject(ApiService);

  readonly agentId = input.required<string>();
  readonly levels  = AUTONOMY_LEVELS;
  readonly entries = signal<AutonomyEntry[]>([]);
  readonly error   = signal<string | null>(null);
  readonly busy    = signal<string | null>(null);
  readonly raisesConsequential = raisesConsequential;

  constructor() {
    effect(() => this.load(this.agentId()));
  }

  load(agentId: string): void {
    this.api.get<Page<AutonomyEntry>>(`/api/v1/admin/ai/agents/${encodeURIComponent(agentId)}/autonomy`).subscribe({
      next: page => this.entries.set(page.items ?? []),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  private url(actionId: string): string {
    return `/api/v1/admin/ai/agents/${encodeURIComponent(this.agentId())}/autonomy/${encodeURIComponent(actionId)}`;
  }

  /** Saves a level, keeping the row's limits; `undoSeconds` and `dailyLimit` when given. */
  save(entry: AutonomyEntry, level: AutonomyLevel, undoSeconds?: number | null, dailyLimit?: number | null): void {
    const row = entry.row;
    this.busy.set(entry.action_id);
    this.error.set(null);
    this.api.put<AutonomyRow>(this.url(entry.action_id), {
      level,
      undo_seconds:       undoSeconds ?? row?.undo_seconds ?? null,
      daily_limit:        dailyLimit === undefined ? (row?.daily_limit ?? null) : dailyLimit,
      money_cap_minor:    row?.money_cap_minor ?? null,
      currency:           row?.currency ?? null,
      owned_records_only: row?.owned_records_only ?? false,
      hours_start:        row?.hours_start ?? null,
      hours_end:          row?.hours_end ?? null,
      time_zone:          row?.time_zone ?? null,
      row_version:        row?.row_version ?? null,
    }).subscribe({
      next: () => { this.busy.set(null); this.load(this.agentId()); },
      error: (e: ApiError) => { this.busy.set(null); this.error.set(e.message); },
    });
  }

  clear(entry: AutonomyEntry): void {
    this.busy.set(entry.action_id);
    this.error.set(null);
    this.api.delete(this.url(entry.action_id)).subscribe({
      next: () => { this.busy.set(null); this.load(this.agentId()); },
      error: (e: ApiError) => { this.busy.set(null); this.error.set(e.message); },
    });
  }

  /** A number input's value, or `null` when empty. */
  numberOrNull(value: string): number | null {
    const n = Number(value);
    return value.trim() === '' || !Number.isFinite(n) ? null : n;
  }
}
