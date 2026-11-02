import { ChangeDetectionStrategy, Component, effect, inject, input, output, signal } from '@angular/core';
import { LangService, TranslatePipe } from '@attome/base';

import { MarketingListExplanation, SegmentInsightService } from './segment-insight.service';

/**
 * Why one person is in a marketing list or not (roadmap E7-T12), from
 * `GET /api/v1/marketing/lists/{id}/explain/{person_id}`: the list's own
 * query or members first, then each combination, with whether that step's
 * list holds the person and whether they are in after it.
 */
@Component({
  selector: 'xrm-member-explain-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <div class="me-backdrop"></div>
    <div class="me" role="dialog" aria-modal="true" aria-labelledby="me-title"
         [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="me">
      <h3 id="me-title">{{ 'segmentInsight.explainTitle' | translate }}</h3>
      @if (explanation(); as e) {
        <p data-testid="me-verdict">
          {{ (e.member ? 'segmentInsight.isMember' : 'segmentInsight.notMember') | translate }}
        </p>
        <ol class="me-steps">
          @for (step of e.steps; track $index) {
            <li data-testid="me-step">
              <span>{{ (step.step === 'base' ? 'segmentInsight.stepBase' : 'segmentInsight.stepCombination') | translate }}</span>
              @if (step.step !== 'base') {
                <bdi dir="ltr">{{ step.step }}</bdi>
              }
              <span>{{ (step.holds ? 'segmentInsight.holds' : 'segmentInsight.doesNotHold') | translate }}</span>
              <span>{{ (step.member_after ? 'segmentInsight.inAfter' : 'segmentInsight.outAfter') | translate }}</span>
            </li>
          }
        </ol>
      } @else if (failed()) {
        <p role="alert">{{ 'segmentInsight.explainFailed' | translate }}</p>
      }
      <button type="button" class="btn" (click)="closed.emit()" data-testid="me-close">
        {{ 'segmentInsight.close' | translate }}
      </button>
    </div>
  `,
  styles: [`
    .me-backdrop { position: fixed; inset: 0; background: var(--color-backdrop, rgb(0 0 0 / .3)); }
    .me {
      position: fixed; inset-block-start: 15%; inset-inline: 0; margin-inline: auto;
      inline-size: min(32rem, calc(100% - 2rem)); padding: 1rem;
      background: var(--color-surface, #fff); border-radius: .5rem; display: grid; gap: .5rem;
    }
    .me-steps { margin: 0; padding-inline-start: 1.25rem; display: grid; gap: .25rem; }
    .me-steps li span + span { margin-inline-start: .5rem; }
  `],
})
export class MemberExplainDialogComponent {
  protected readonly lang = inject(LangService);
  private readonly insight = inject(SegmentInsightService);

  readonly listId = input.required<string>();
  readonly personId = input.required<string>();
  readonly closed = output<void>();

  readonly explanation = signal<MarketingListExplanation | null>(null);
  readonly failed = signal(false);

  constructor() {
    effect(() => {
      const list = this.listId();
      const person = this.personId();
      if (!list || !person) return;
      this.explanation.set(null);
      this.failed.set(false);
      this.insight.explain(list, person).subscribe({
        next: e => this.explanation.set(e),
        error: () => this.failed.set(true),
      });
    });
  }
}
