import { ChangeDetectionStrategy, Component, input } from '@angular/core';

export interface ChoicePillStyle {
  color?: string | null;
  icon?: string | null;
}

/**
 * Renders a single `choice` field value as plain text unless an admin has
 * configured a color and/or icon for it (`ChoiceOptions.choice_styles`), in
 * which case it renders as a colored chip — so every existing choice field
 * with no configured styles keeps today's plain-text grid cell unchanged.
 *
 *   <xrm-choice-pill value="Outbound" [style]="{ color: '#22c55e', icon: 'las la-arrow-up' }" />
 *
 * Three cases, one markup shape:
 * - no color, no icon  -> plain text (unchanged default)
 * - icon, no color     -> neutral bordered chip with the icon (e.g. Channel)
 * - color (± icon)     -> tinted chip; a dot stands in for a missing icon
 *                         (e.g. Status/Direction)
 */
@Component({
  selector: 'xrm-choice-pill',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./choice-pill.component.css'],
  templateUrl: './choice-pill.component.html',
})
export class ChoicePillComponent {
  readonly value = input.required<string>();
  readonly style = input<ChoicePillStyle | null | undefined>(null);

  protected pillBg(): string | null {
    const color = this.style()?.color;
    return color ? `color-mix(in srgb, ${color} 16%, transparent)` : null;
  }

  protected pillBorder(): string | null {
    const color = this.style()?.color;
    return color ? `color-mix(in srgb, ${color} 45%, transparent)` : null;
  }
}
