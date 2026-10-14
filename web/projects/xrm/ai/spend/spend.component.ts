import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** One money window (`spend_report::SpendLine`). */
export interface SpendLine {
  scope:    'spend_deployment' | 'spend_feature' | 'spend_agent' | string;
  key:      string;
  spent:    number;
  cap:      number;
  percent:  number;
  forecast: number;
}

/** `GET /api/v1/admin/ai/spend` (`spend_report::SpendReport`). */
export interface SpendReport {
  model:              string;
  priced:             boolean;
  degrade_at_percent: number;
  window_days:        number;
  lines:              SpendLine[];
}

/** Where a line stands: within, near its cap (shortened), or at it (refused). */
export function spendState(line: SpendLine, degradeAt: number): 'ok' | 'near' | 'over' {
  if (line.percent >= 100) return 'over';
  if (line.percent >= degradeAt) return 'near';
  return 'ok';
}

/** Whether the month's forecast passes the cap. */
export function forecastOver(line: SpendLine): boolean {
  return line.cap > 0 && line.forecast > line.cap;
}

/**
 * AI spend (roadmap N24-T2): this rolling month's spend against each money
 * cap — the deployment, each capped feature, each agent — with the
 * forecast for the whole month. Reads the same counters the budget guard
 * enforces. Logical CSS only.
 */
@Component({
  selector:        'xrm-ai-spend',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './spend.component.html',
  styleUrls:       ['./spend.component.css'],
})
export class AiSpendComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly report = signal<SpendReport | null>(null);
  readonly error  = signal<string | null>(null);

  readonly stateOf = spendState;
  readonly forecastOver = forecastOver;

  ngOnInit(): void {
    this.api.get<SpendReport>('/api/v1/admin/ai/spend').subscribe({
      next: report => this.report.set(report),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** A bar width in percent, never past the track. */
  width(line: SpendLine): number {
    return Math.max(0, Math.min(100, line.percent));
  }
}
