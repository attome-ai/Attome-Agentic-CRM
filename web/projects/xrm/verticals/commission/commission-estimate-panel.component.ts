import { ChangeDetectionStrategy, Component, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiService, LocalNumberPipe, TranslatePipe } from '@attome/base';

/** `attome_commission::statement::CommissionEstimate`. */
export interface CommissionEstimate {
  period_id: string;
  participant_id: string;
  payout: number | string;
  period_change: number | string;
}

/**
 * The commission estimator on a deal (roadmap F10-T15): what winning this
 * deal would pay the reader in the current period, worked out by the
 * server from their published plan without writing anything. It stays
 * hidden for a reader on no plan (the route answers 403 or 404).
 */
@Component({
  selector: 'xrm-commission-estimate-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, TranslatePipe],
  template: `
    @if (available()) {
      <section class="ce" aria-labelledby="ce-title">
        <h3 id="ce-title">{{ 'commission.estimate.title' | translate }}</h3>
        @if (estimate(); as e) {
          <dl>
            <dt>{{ 'commission.estimate.payout' | translate }}</dt><dd data-payout>{{ +e.payout | localNumber }}</dd>
            <dt>{{ 'commission.estimate.change' | translate }}</dt><dd>{{ +e.period_change | localNumber }}</dd>
          </dl>
        } @else {
          <button type="button" (click)="run()" [disabled]="busy()">{{ 'commission.estimate.run' | translate }}</button>
        }
      </section>
    }
  `,
  styles: [`
    :host { display: block; }
    .ce { display: flex; flex-direction: column; gap: 0.5rem; padding-block: 0.75rem;
      border-block-start: 1px solid var(--color-border); }
    .ce h3 { margin-block: 0; font-size: 1rem; }
    .ce dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 0.75rem; margin: 0; }
    .ce dd { margin: 0; }
  `],
})
export class CommissionEstimatePanelComponent {
  private readonly api = inject(ApiService);

  readonly opportunityId = input<string | null>(null);

  readonly estimate = signal<CommissionEstimate | null>(null);
  readonly available = signal(true);
  readonly busy = signal(false);

  constructor() {
    effect(() => {
      this.opportunityId();
      untracked(() => { this.estimate.set(null); this.available.set(true); });
    });
  }

  run(): void {
    const id = this.opportunityId();
    if (!id) return;
    this.busy.set(true);
    this.api.post<CommissionEstimate>('/api/v1/commission/estimate', { opportunity_id: id }).subscribe({
      next: e => { this.busy.set(false); this.estimate.set(e); },
      // On no plan, or not the reader's deal: nothing to estimate.
      error: () => { this.busy.set(false); this.available.set(false); },
    });
  }
}
