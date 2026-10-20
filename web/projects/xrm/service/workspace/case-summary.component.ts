import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { ApiService, TranslatePipe } from '@attome/base';

interface SummaryOutcome {
  status: string;
  result?: { summary?: string; cached?: boolean };
}

/** The summary text in an action outcome, if it completed. Pure. */
export function summaryText(outcome: SummaryOutcome | null | undefined): string | null {
  if (!outcome || outcome.status !== 'completed') return null;
  const text = outcome.result?.summary;
  return typeof text === 'string' && text.trim() ? text : null;
}

/**
 * G1-T3: the case's AI summary in the workspace context panel. The server
 * makes it for the assignee two minutes after the thread goes quiet, so
 * opening the case is usually a cache hit; "Refresh" asks again. When AI is
 * off, unlicensed or refused, the panel shows nothing rather than an error.
 */
@Component({
  selector: 'xrm-service-case-summary',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (available()) {
      <section class="case-summary" [attr.aria-label]="'serviceCaseSummary.title' | translate">
        <h4>{{ 'serviceCaseSummary.title' | translate }}</h4>
        @if (loading()) {
          <p class="hint" data-testid="case-summary-loading">{{ 'serviceCaseSummary.loading' | translate }}</p>
        } @else if (summary(); as text) {
          <p class="case-summary-text" data-testid="case-summary-text">{{ text }}</p>
        } @else {
          <p class="hint">{{ 'serviceCaseSummary.none' | translate }}</p>
        }
        <button type="button" class="btn-secondary" data-testid="case-summary-refresh"
                [disabled]="loading()" (click)="load()">
          {{ 'serviceCaseSummary.refresh' | translate }}
        </button>
      </section>
    }
  `,
  styles: [`
    .case-summary { margin-block: var(--space-3, 12px); }
    .case-summary h4 { margin-block: 0 var(--space-1, 4px); }
    .case-summary-text { white-space: pre-line; margin-block: 0 var(--space-2, 8px); }
  `],
})
export class CaseSummaryComponent {
  private readonly api = inject(ApiService);

  readonly entity = input.required<string>();
  readonly recordId = input.required<string>();

  readonly summary = signal<string | null>(null);
  readonly loading = signal(false);
  /** False once the action is refused: AI is not available to this person. */
  readonly available = signal(true);

  constructor() {
    effect(() => {
      // A new case loads its own summary.
      this.entity();
      this.recordId();
      this.summary.set(null);
      this.available.set(true);
      this.load();
    });
  }

  load(): void {
    const entity = this.entity();
    const recordId = this.recordId();
    if (!entity || !recordId) return;
    this.loading.set(true);
    this.api
      .post<SummaryOutcome>('/api/v1/actions/record.summarize/invoke', {
        args: { entity, record_id: recordId },
      })
      .subscribe({
        next: outcome => {
          this.summary.set(summaryText(outcome));
          this.loading.set(false);
        },
        error: () => {
          this.available.set(false);
          this.loading.set(false);
        },
      });
  }
}
