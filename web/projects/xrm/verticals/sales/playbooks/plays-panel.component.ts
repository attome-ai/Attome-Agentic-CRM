import { ChangeDetectionStrategy, Component, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiService, LangService, TranslatePipe } from '@attome/base';

/** `attome_sales::plays::SalesPlayStep`. */
export interface SalesPlayStep {
  id: string;
  title: string | null;
  guidance: string | null;
  step_order: number | null;
  due_after_days: number | null;
  activity_kind: string | null;
}

/** `attome_sales::plays::SalesPlay`. */
export interface SalesPlay {
  playbook_id: string;
  name: string | null;
  name_ar: string | null;
  steps: SalesPlayStep[];
}

/**
 * The plays panel on a deal (roadmap D26-T2): the playbooks whose condition
 * holds for this deal right now (the server evaluates each playbook's
 * `trigger_condition` against the deal as the user reads it, so a play for
 * the proposal stage shows while the deal is in proposal), each with its
 * steps in order. It stays hidden when no play applies or playbooks are not
 * installed (the route answers 404). Text comes from the catalogue, a
 * playbook's Arabic name is used in Arabic, and layout uses logical
 * properties only.
 */
@Component({
  selector: 'xrm-plays-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (plays().length) {
      <section class="pp" aria-labelledby="pp-title">
        <h3 id="pp-title">{{ 'plays.title' | translate }}</h3>
        @for (play of plays(); track play.playbook_id) {
          <article class="pp-play" [attr.data-play]="play.playbook_id">
            <h4>{{ name(play) }}</h4>
            @if (play.steps.length) {
              <ol class="pp-steps" [attr.aria-label]="'plays.steps' | translate">
                @for (step of play.steps; track step.id) {
                  <li [attr.data-step]="step.id">
                    <div class="pp-step-head">
                      @if (step.activity_kind) {
                        <span class="pp-kind">{{ 'plays.activity.' + step.activity_kind | translate }}</span>
                      }
                      <strong>{{ step.title }}</strong>
                      @if (step.due_after_days !== null) {
                        <small>{{ 'plays.dueAfter' | translate: { days: step.due_after_days } }}</small>
                      }
                    </div>
                    @if (step.guidance) { <p>{{ step.guidance }}</p> }
                  </li>
                }
              </ol>
            } @else {
              <p class="pp-muted">{{ 'plays.noSteps' | translate }}</p>
            }
          </article>
        }
      </section>
    }
  `,
  styles: [`
    :host { display: block; }
    .pp { display: flex; flex-direction: column; gap: 0.75rem; padding-block: 0.75rem;
      border-block-start: 1px solid var(--color-border); }
    .pp h3 { margin-block: 0; font-size: 1rem; }
    .pp h4 { margin-block: 0 0.375rem; font-size: 0.875rem; }
    .pp-play { padding-block: 0.5rem; padding-inline: 0.75rem; border: 1px solid var(--color-border);
      border-radius: 0.5rem; }
    .pp-steps { margin: 0; padding-inline-start: 1.25rem; display: flex; flex-direction: column; gap: 0.5rem; }
    .pp-step-head { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: baseline; }
    .pp-step-head small { color: var(--color-text-secondary); }
    .pp-kind { font-size: 0.75rem; padding-inline: 0.375rem; border-radius: 0.25rem;
      background: var(--color-bg-alt); }
    .pp-steps p { margin-block: 0.25rem 0; white-space: pre-wrap; color: var(--color-text-secondary); }
    .pp-muted { color: var(--color-text-secondary); font-size: 0.8125rem; margin: 0; }
  `],
})
export class PlaysPanelComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  readonly opportunityId = input<string | null>(null);
  /** The deal's stage, so the panel reloads when the stage changes. */
  readonly stage = input<string | null>(null);

  readonly plays = signal<SalesPlay[]>([]);

  constructor() {
    // Only the deal and its stage are tracked: loading writes the panel's
    // own signal, which must not re-run this effect.
    effect(() => {
      const id = this.opportunityId();
      this.stage();
      untracked(() => {
        this.plays.set([]);
        if (id) this.load(id);
      });
    });
  }

  /** The playbook's name in the reader's language. */
  name(play: SalesPlay): string {
    const arabic = this.lang.current() === 'ar' && play.name_ar ? play.name_ar : null;
    return arabic ?? play.name ?? '';
  }

  private load(id: string): void {
    // A 404 means playbooks are not installed: the panel stays hidden.
    this.api.get<{ items: SalesPlay[] }>(`/api/v1/sales/opportunities/${encodeURIComponent(id)}/plays`).subscribe({
      next: page => { if (this.opportunityId() === id) this.plays.set(page.items); },
      error: () => this.plays.set([]),
    });
  }
}
