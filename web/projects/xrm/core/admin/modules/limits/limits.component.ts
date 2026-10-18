import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { SettingsService } from '@attome/xrm/core/admin/data';

/** `attome_api::limits_admin::LimitView`. */
export interface LimitView {
  key: string;
  purpose: string;
  kind: string;
  /** `boot_config` or `runtime_setting`. */
  scope: string;
  value: number;
  default: number;
  floor: number;
  ceiling: number;
  unit: string;
  hits_7d: number;
  peak_7d: number;
  warning: boolean;
}

/** The seven-day peak as a share of the value, 0 to 100. */
export function peakPercent(limit: LimitView): number {
  if (limit.value <= 0) return 0;
  return Math.min(100, Math.round((limit.peak_7d / limit.value) * 100));
}

/** Whether `value` is a whole number inside the limit's range. */
export function inRange(limit: LimitView, value: number | null): boolean {
  return value !== null && Number.isInteger(value) && value >= limit.floor && value <= limit.ceiling;
}

/**
 * Limits (roadmap AA9-T8): every limit the server enforces, its value and
 * range, its seven-day peak against the value and a warning chip when it
 * nears or reached it. A runtime limit is raised here within its range
 * through the audited settings route; a boot-config limit names the
 * configuration file instead. Logical CSS only.
 */
@Component({
  selector: 'xrm-limits',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="lim">
      <h3>{{ 'limitsPage.title' | translate }}</h3>
      <p class="lim-muted">{{ 'limitsPage.intro' | translate }}</p>
      @if (error(); as message) { <p class="lim-error" role="alert">{{ message }}</p> }
      <ul class="lim-list">
        @for (limit of limits(); track limit.key) {
          <li [attr.data-key]="limit.key">
            <div class="lim-head">
              <span class="lim-key" dir="ltr">{{ limit.key }}</span>
              @if (limit.warning) {
                <span class="lim-chip" role="status">{{ 'limitsPage.warning' | translate }}</span>
              }
            </div>
            <small class="lim-muted">{{ limit.purpose }}</small>
            <div class="lim-figures">
              <span>{{ 'limitsPage.value' | translate: { value: limit.value, unit: limit.unit } }}</span>
              <span class="lim-muted">{{ 'limitsPage.range' | translate: { floor: limit.floor, ceiling: limit.ceiling } }}</span>
            </div>
            <div class="lim-bar" role="meter" aria-valuemin="0" aria-valuemax="100"
                 [attr.aria-valuenow]="peak(limit)"
                 [attr.aria-label]="'limitsPage.peak' | translate: { percent: peak(limit) }">
              <span [style.inline-size.%]="peak(limit)" [class.lim-hot]="limit.warning"></span>
            </div>
            <small class="lim-muted">{{ 'limitsPage.peak' | translate: { percent: peak(limit) } }}</small>
            @if (limit.scope === 'runtime_setting') {
              @if (editing() === limit.key) {
                <form class="lim-raise" (submit)="$event.preventDefault(); save(limit)">
                  <label>
                    {{ 'limitsPage.newValue' | translate }}
                    <input type="number" step="1" [min]="limit.floor" [max]="limit.ceiling"
                           [value]="draft() ?? ''" (input)="setDraft($event)" />
                  </label>
                  @if (!inRange(limit, draft())) {
                    <small class="lim-error">{{ 'limitsPage.outOfRange' | translate: { floor: limit.floor, ceiling: limit.ceiling } }}</small>
                  }
                  <button type="submit" [disabled]="busy() || !inRange(limit, draft())">{{ 'limitsPage.save' | translate }}</button>
                  <button type="button" (click)="cancel()">{{ 'limitsPage.cancel' | translate }}</button>
                </form>
              } @else {
                <button type="button" class="lim-raise-btn" (click)="edit(limit)">{{ 'limitsPage.raise' | translate }}</button>
              }
            } @else {
              <small class="lim-muted lim-config">{{ 'limitsPage.inConfig' | translate }}</small>
            }
          </li>
        } @empty {
          <li class="lim-muted">{{ 'limitsPage.none' | translate }}</li>
        }
      </ul>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .lim { display: flex; flex-direction: column; gap: 0.75rem; }
    .lim h3 { margin-block: 0; font-size: 1rem; }
    .lim-list { list-style: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 0.5rem; }
    .lim-list li { display: flex; flex-direction: column; gap: 0.25rem;
      padding-block: 0.5rem; border-block-end: 1px solid var(--color-border); }
    .lim-head, .lim-figures { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .lim-key { font-weight: 600; }
    .lim-chip { padding-inline: 0.5rem; border-radius: 999px; font-size: 0.75rem;
      background: var(--color-warning-subtle, var(--color-border)); color: var(--color-warning, inherit); }
    .lim-bar { block-size: 0.375rem; inline-size: 100%; max-inline-size: 24rem;
      background: var(--color-border); border-radius: 999px; overflow: hidden; }
    .lim-bar span { display: block; block-size: 100%; background: var(--color-primary); }
    .lim-bar span.lim-hot { background: var(--color-warning, var(--color-danger)); }
    .lim-raise { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
    .lim-raise input { inline-size: 10rem; margin-inline-start: 0.25rem; }
    .lim-raise-btn { align-self: flex-start; }
    .lim-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .lim-error { color: var(--color-danger); }
  `],
})
export class LimitsComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly settings = inject(SettingsService);

  readonly limits = signal<LimitView[]>([]);
  readonly error = signal<string | null>(null);
  readonly busy = signal(false);
  /** The key of the limit being raised, if any. */
  readonly editing = signal<string | null>(null);
  readonly draft = signal<number | null>(null);
  readonly peak = peakPercent;
  readonly inRange = inRange;

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<{ items: LimitView[] }>('/api/v1/admin/limits').subscribe({
      next: body => this.limits.set(body.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  edit(limit: LimitView): void {
    this.editing.set(limit.key);
    this.draft.set(limit.value);
  }

  cancel(): void {
    this.editing.set(null);
    this.draft.set(null);
  }

  setDraft(event: Event): void {
    const raw = (event.target as HTMLInputElement).value;
    this.draft.set(raw === '' ? null : Number(raw));
  }

  /** Stores the new value as the `limits.{key}` setting; never outside the range. */
  save(limit: LimitView): void {
    const value = this.draft();
    if (limit.scope !== 'runtime_setting' || !inRange(limit, value)) return;
    this.busy.set(true);
    this.settings.putAdminSetting(`limits.${limit.key}`, 'deployment', value).subscribe({
      next: () => { this.busy.set(false); this.cancel(); this.load(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
