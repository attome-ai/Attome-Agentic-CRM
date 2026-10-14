import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `GET /api/v1/admin/ai/status` (`ai_status::AiStatus`). */
export interface AiStatus {
  generation_model: string;
  model_approved:   boolean;
  model_cards: {
    id: string; name: string | null; version: string | null; provider_model_id: string | null;
    approval_status: string | null; context_window: number | null; max_output_tokens: number | null;
    knowledge_cutoff: string | null; description: string | null;
  }[];
  switched_off:   number;
  turns_last_day: { terminal_state: string; turns: number }[];
  timeline: {
    scope_kind: string; scope_key: string; enabled: boolean; cause: string;
    reason: string | null; changed_at: string;
  }[];
}

/** One word for the page's headline: down, degraded or up. */
export function overall(status: AiStatus): 'down' | 'degraded' | 'up' {
  if (!status.generation_model || !status.model_approved) return 'down';
  if (status.switched_off > 0) return 'degraded';
  return 'up';
}

/**
 * The AI status page (roadmap N31-T2): the model in use and its card, what
 * is switched off, how turns ended over the last day, and the incident
 * timeline (the latest switch changes). Logical CSS only.
 */
@Component({
  selector:        'xrm-ai-status',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [LocalDatePipe, TranslatePipe],
  templateUrl:     './status.component.html',
  styleUrls:       ['./status.component.css'],
})
export class AiStatusComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly status = signal<AiStatus | null>(null);
  readonly error  = signal<string | null>(null);
  readonly overall = overall;

  ngOnInit(): void {
    this.api.get<AiStatus>('/api/v1/admin/ai/status').subscribe({
      next: status => this.status.set(status),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
