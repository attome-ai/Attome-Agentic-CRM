import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { LocalNumberPipe, TranslatePipe } from '@attome/base';

/**
 * L6-T7: how full a field is in the entity's latest data profile, as a
 * small badge on the field list. Nothing renders when the field has no
 * profile (`null`): an unprofiled field is not an empty one.
 */
@Component({
  selector: 'xrm-fill-rate-badge',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, TranslatePipe],
  template: `
    @let r = rate();
    @if (r !== null && r !== undefined) {
      <span class="fr-badge" [class]="'fr-badge fr-' + band()" data-fill-rate
            [attr.title]="'governance.catalog.profile.fillRateHint' | translate">
        {{ 'governance.catalog.profile.fillRate' | translate: { pct: (r | localNumber: { maximumFractionDigits: 0 }) } }}
      </span>
    }
  `,
  styles: [`
    .fr-badge { display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; inline-size: fit-content; }
    .fr-good { background: var(--color-success-bg, #e6f4ea); color: var(--color-success, #1e7a3a); }
    .fr-fair { background: var(--color-warning-bg, #fff4e0); color: var(--color-warning, #8a5a00); }
    .fr-poor { background: var(--color-danger-bg, #fde8e8); color: var(--color-danger, #b42318); }
  `],
})
export class FillRateBadgeComponent {
  /** The fill rate, 0–100, or `null` when the field was not profiled. */
  readonly rate = input<number | null | undefined>(null);

  readonly band = computed(() => {
    const r = this.rate() ?? 0;
    return r >= 90 ? 'good' : r >= 50 ? 'fair' : 'poor';
  });
}
