import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `trial::ActionAgreement`. */
export interface ActionAgreement {
  action_id: string;
  same:      number;
  different: number;
  none:      number;
  pending:   number;
}

/** `trial::DifferentDecision`. */
export interface DifferentDecision {
  id:               string;
  action_id:        string;
  args:             unknown;
  target_entity:    string | null;
  target_record_id: string | null;
  created_at:       string;
}

/** `trial::TrialReport`. */
export interface TrialReport {
  same:             number;
  different:        number;
  none:             number;
  pending:          number;
  agreement:        number | null;
  per_action:       ActionAgreement[];
  different_sample: DifferentDecision[];
  min_compared:     number;
}

/** Whole-percent agreement, or `null` before anything was compared. */
export function percent(agreement: number | null): number | null {
  return agreement === null ? null : Math.round(agreement * 100);
}

/**
 * An agent's trial (roadmap AH6): while its definition is in testing it runs
 * on real triggers but records its writes instead of making them; this shows
 * how often it agreed with what people did, where it did not, and lets an
 * administrator take it live above an agreement threshold. Logical CSS only.
 */
@Component({
  selector:        'xrm-ai-agent-trial',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [LocalDatePipe, TranslatePipe],
  templateUrl:     './agent-trial.component.html',
  styleUrls:       ['./autonomy.component.css'],
})
export class AiAgentTrialComponent {
  private readonly api = inject(ApiService);

  readonly agentId      = input.required<string>();
  readonly report       = signal<TrialReport | null>(null);
  readonly error        = signal<string | null>(null);
  readonly busy         = signal(false);
  readonly wentLive     = signal(false);
  readonly minAgreement = signal(90);
  readonly percent      = percent;
  /** Going live needs this many decisions compared with an outcome. */
  readonly enoughCompared = computed(() => {
    const r = this.report();
    return !!r && r.same + r.different >= r.min_compared;
  });

  constructor() {
    effect(() => this.load(this.agentId()));
  }

  load(agentId: string): void {
    this.api.get<TrialReport>(`/api/v1/admin/ai/agents/${encodeURIComponent(agentId)}/trial-report`).subscribe({
      next: r => this.report.set(r),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** The agent's proposed arguments, as quoted text. */
  quoted(args: unknown): string {
    return JSON.stringify(args);
  }

  goLive(): void {
    const id = encodeURIComponent(this.agentId());
    this.busy.set(true);
    this.error.set(null);
    this.api.get<{ row_version: number }>(`/api/v1/ai_agent/${id}`).subscribe({
      next: record => {
        this.api.post<TrialReport>(`/api/v1/admin/ai/agents/${id}/go-live`, {
          row_version:   record.row_version,
          min_agreement: this.minAgreement() / 100,
        }).subscribe({
          next: () => { this.busy.set(false); this.wentLive.set(true); },
          error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
        });
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
