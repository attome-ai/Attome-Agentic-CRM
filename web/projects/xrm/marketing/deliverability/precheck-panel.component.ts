import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { LangService, TranslatePipe } from '@attome/base';

import type { PrecheckFinding, PrecheckReport } from './deliverability.service';

const COST: Record<PrecheckFinding['severity'], number> = { error: 40, warning: 15, info: 5 };

/**
 * The findings in the order they cost the score, the costliest first; equal
 * costs keep the server's order. Pure.
 */
export function orderFindings(findings: readonly PrecheckFinding[]): PrecheckFinding[] {
  return findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => COST[b.f.severity] - COST[a.f.severity] || a.i - b.i)
    .map(x => x.f);
}

/**
 * A send's pre-send check (roadmap E6-T10, E6-T13): the score out of 100,
 * whether it passes, and each finding with its guidance, costliest first.
 */
@Component({
  selector: 'xrm-deliverability-precheck',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="dp" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="dpc-title" data-testid="dpc">
      <h3 id="dpc-title">{{ 'marketingDeliverability.precheck' | translate }}</h3>
      @if (report(); as r) {
        <p class="dp-score" [class.dp-pass]="r.passed" data-testid="dpc-score">
          {{ 'marketingDeliverability.score' | translate }}
          <strong dir="ltr">{{ r.score }}/100</strong>
          · {{ (r.passed ? 'marketingDeliverability.passed' : 'marketingDeliverability.failed') | translate }}
        </p>
        @if (ordered().length) {
          <ol class="dp-findings">
            @for (f of ordered(); track $index) {
              <li [class]="'dp-' + f.severity" data-testid="dpc-finding" [attr.data-code]="f.code">
                <span class="dp-sev">{{ 'marketingDeliverability.severity.' + f.severity | translate }}</span>
                {{ f.guidance_key | translate }}
                @if (f.detail) { <span class="dp-detail" dir="ltr">{{ f.detail }}</span> }
              </li>
            }
          </ol>
        }
      } @else {
        <p class="dp-empty">{{ 'marketingDeliverability.noPrecheck' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .dp-score { font-size: 1.125rem; color: var(--color-danger, #c53030); }
    .dp-score.dp-pass { color: var(--color-success, #2f855a); }
    .dp-findings { margin: 0; padding-inline-start: 1.25rem; display: grid; gap: .25rem; }
    .dp-sev { font-weight: 600; margin-inline-end: .25rem; }
    .dp-error .dp-sev { color: var(--color-danger, #c53030); }
    .dp-warning .dp-sev { color: var(--color-warning, #b7791f); }
    .dp-detail { margin-inline-start: .5rem; color: var(--color-text-secondary, #666); }
  `],
})
export class PrecheckPanelComponent {
  protected readonly lang = inject(LangService);
  /** The check's answer; null before one has run. */
  readonly report = input<PrecheckReport | null>(null);
  protected readonly ordered = computed(() => orderFindings(this.report()?.findings ?? []));
}
