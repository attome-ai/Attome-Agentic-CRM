import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** `recycle_bin::BinSetting`. */
export interface BinSetting {
  entity: string;
  require_reason: boolean;
  retention_days: number | null;
  alert_threshold: number;
  hard_delete_needs_approval: boolean;
}

/**
 * The retention choices: `null` follows the deployment's purge grace; the
 * route takes 1 to 3,650 days, so there is no "forever".
 */
export const RETENTION_CHOICES: readonly (number | null)[] = [null, 7, 30, 365, 2555];

/**
 * A18-T9: one entity's recycle-bin rules (`PUT /api/v1/admin/bin-settings/{entity}`):
 * how long deleted records stay, whether deleting needs a reason, how many
 * deletes in ten minutes alert the administrators, and whether a permanent
 * delete waits for a second person.
 */
@Component({
  selector: 'xrm-bin-settings',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <form class="bs" (ngSubmit)="save()" data-bin-settings>
      <label class="bs-row">
        <span>{{ 'binSettings.retention' | translate }}</span>
        <select name="retention" [ngModel]="retention()" (ngModelChange)="retention.set($event)">
          @for (days of choices; track days) {
            <option [ngValue]="days">
              {{ days === null ? ('binSettings.retentionDefault' | translate) : ('binSettings.retentionDays' | translate: { days }) }}
            </option>
          }
        </select>
      </label>
      <label class="bs-check">
        <input type="checkbox" name="requireReason" [ngModel]="requireReason()" (ngModelChange)="requireReason.set($event)" />
        {{ 'binSettings.requireReason' | translate }}
      </label>
      <label class="bs-check">
        <input type="checkbox" name="approval" [ngModel]="approval()" (ngModelChange)="approval.set($event)" />
        {{ 'binSettings.hardDeleteApproval' | translate }}
      </label>
      <label class="bs-row">
        <span>{{ 'binSettings.alertThreshold' | translate }}</span>
        <input type="number" name="threshold" min="1" max="100000" dir="ltr"
               [ngModel]="threshold()" (ngModelChange)="threshold.set($event)" />
      </label>
      <div class="bs-actions">
        <button type="submit" class="btn btn-primary" [disabled]="busy()">{{ 'binSettings.save' | translate }}</button>
        @if (saved()) { <span role="status">{{ 'binSettings.saved' | translate }}</span> }
        @if (error(); as message) { <span class="bs-error" role="alert">{{ message }}</span> }
      </div>
    </form>
  `,
  styles: [`
    .bs { display: flex; flex-direction: column; gap: 0.625rem; max-inline-size: 32rem; }
    .bs-row { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 0.5rem; }
    .bs-row input { inline-size: 8rem; }
    .bs-check { display: flex; align-items: center; gap: 0.5rem; }
    .bs-actions { display: flex; align-items: center; gap: 0.75rem; }
    .bs-error { color: var(--color-danger); }
  `],
})
export class BinSettingsComponent {
  private readonly api = inject(ApiService);

  /** Entity logical name. */
  readonly entity = input.required<string>();

  choices: readonly (number | null)[] = RETENTION_CHOICES;
  readonly retention = signal<number | null>(null);
  readonly requireReason = signal(false);
  readonly approval = signal(false);
  readonly threshold = signal(100);
  readonly busy = signal(false);
  readonly saved = signal(false);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => this.load(this.entity()));
  }

  private load(entity: string): void {
    this.api.get<{ items: BinSetting[] }>('/api/v1/admin/bin-settings').subscribe({
      next: page => this.apply(page.items.find(s => s.entity === entity)),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  private apply(setting: BinSetting | undefined): void {
    const retention = setting?.retention_days ?? null;
    // A value set through the API that is not one of the choices still shows.
    if (!this.choices.includes(retention)) this.choices = [...RETENTION_CHOICES, retention].sort(byDays);
    this.retention.set(retention);
    this.requireReason.set(setting?.require_reason ?? false);
    this.approval.set(setting?.hard_delete_needs_approval ?? false);
    this.threshold.set(setting?.alert_threshold ?? 100);
  }

  save(): void {
    this.busy.set(true);
    this.saved.set(false);
    this.error.set(null);
    this.api.put<BinSetting>(`/api/v1/admin/bin-settings/${encodeURIComponent(this.entity())}`, {
      require_reason: this.requireReason(),
      retention_days: this.retention(),
      alert_threshold: Number(this.threshold()),
      hard_delete_needs_approval: this.approval(),
    }).subscribe({
      next: setting => { this.busy.set(false); this.saved.set(true); this.apply(setting); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}

/** The default (`null`) first, then shortest to longest. */
function byDays(a: number | null, b: number | null): number {
  return (a ?? -1) - (b ?? -1);
}
