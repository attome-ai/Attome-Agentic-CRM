import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';

export interface ToggleOption {
  id: string;
  title: string;
  description: string;
  icon: string;
  active: boolean;
  /** A second, smaller line (Y4-T5: version, dependencies, usage). */
  detail?: string;
  /** The switch cannot be changed (Y4-T5: another module needs this one). */
  locked?: boolean;
}

export interface ToggleOptionChange {
  id: string;
  active: boolean;
}

@Component({
  selector: 'xrm-toggle-option-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./toggle-option-grid.component.css'],
  templateUrl: './toggle-option-grid.component.html',
})
export class ToggleOptionGridComponent {
  readonly title = input('Options');
  readonly options = input.required<readonly ToggleOption[]>();
  readonly disabled = input(false);
  readonly enableAllLabel = input('Enable all');
  readonly disableAllLabel = input('Disable all');

  readonly optionChange = output<ToggleOptionChange>();
  readonly setAll = output<boolean>();

  readonly activeCount = computed(() => this.options().filter(option => option.active).length);

  changeOption(id: string, event: Event): void {
    this.optionChange.emit({ id, active: (event.target as HTMLInputElement).checked });
  }
}
