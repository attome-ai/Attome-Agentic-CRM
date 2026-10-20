import { ChangeDetectionStrategy, Component, inject, input } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { LangService, TranslatePipe } from '@attome/base';

import type { DeliverabilityAlert } from './deliverability.service';

/**
 * The deliverability alerts raised by the daily evaluation (roadmap E6-T10)
 * with what to do about each (E6-T13): the kind, the sending domain or
 * blocklisted target, the figure against its limit, and the guidance text
 * from the catalog (`deliverabilityAlert.<kind>`). Figures and domains stay
 * left to right inside Arabic text.
 */
@Component({
  selector: 'xrm-deliverability-guidance',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DecimalPipe, TranslatePipe],
  template: `
    <section class="dg" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="dg-title" data-testid="dg">
      <h3 id="dg-title">{{ 'marketingDeliverability.alerts' | translate }}</h3>
      @if (alerts().length === 0) {
        <p class="dg-empty" data-testid="dg-empty">{{ 'marketingDeliverability.noAlerts' | translate }}</p>
      } @else {
        <ul class="dg-list">
          @for (a of alerts(); track a.day + a.kind + a.subject) {
            <li class="dg-item" [class.dg-high]="a.kind !== 'reputation_drop'" data-testid="dg-item">
              <div class="dg-head">
                <strong>{{ 'marketingDeliverability.kind.' + a.kind | translate }}</strong>
                <span class="dg-subject" dir="ltr">{{ a.subject }}</span>
                <span class="dg-day" dir="ltr">{{ a.day }}</span>
              </div>
              @if (a.threshold > 0) {
                <p class="dg-figure">
                  <span dir="ltr">{{ a.value | number: '1.0-2' }}%</span>
                  · {{ 'marketingDeliverability.limit' | translate }}
                  <span dir="ltr">{{ a.threshold | number: '1.0-2' }}%</span>
                </p>
              }
              <p class="dg-guidance" data-testid="dg-guidance">{{ a.guidance_key | translate }}</p>
            </li>
          }
        </ul>
      }
    </section>
  `,
  styles: [`
    .dg-list { list-style: none; margin: 0; padding: 0; display: grid; gap: .5rem; }
    .dg-item { border-inline-start: 4px solid var(--color-warning, #b7791f); padding-inline-start: .75rem; padding-block: .25rem; }
    .dg-item.dg-high { border-inline-start-color: var(--color-danger, #c53030); }
    .dg-head { display: flex; flex-wrap: wrap; gap: .5rem; align-items: baseline; }
    .dg-day, .dg-figure { color: var(--color-text-secondary, #666); font-size: .875rem; }
    .dg-guidance { margin-block: .25rem 0; }
  `],
})
export class GuidancePanelComponent {
  protected readonly lang = inject(LangService);
  /** The alerts to show, newest first. */
  readonly alerts = input<readonly DeliverabilityAlert[]>([]);
}
