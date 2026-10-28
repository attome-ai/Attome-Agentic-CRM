import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_ops::maintenance::Maintenance`. */
export interface MaintenanceWindow {
  id: string;
  title_en: string;
  title_ar: string | null;
  components: string[];
  starts_at: string;
  ends_at: string;
  audience: 'internal' | 'public';
  cancelled_at: string | null;
  row_version: number;
}

/** A `datetime-local` value as an ISO moment, or `null`. Pure. */
export function localToIso(value: string): string | null {
  if (!value) return null;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? null : at.toISOString();
}

/** Why a window cannot be planned, as a catalogue key, or `null`. Pure. */
export function windowProblem(titleEn: string, titleAr: string, starts: string | null, ends: string | null, now = Date.now()): string | null {
  if (!titleEn.trim() || !titleAr.trim()) return 'ops.status.bothTitles';
  if (!starts || !ends) return 'ops.status.needTimes';
  if (Date.parse(ends) <= Date.parse(starts)) return 'ops.status.endAfterStart';
  if (Date.parse(starts) <= now) return 'ops.status.startInFuture';
  return null;
}

/**
 * AB11-T9 — planned maintenance: the windows of the next 30 days, a form to
 * plan one (both titles, a future start, a later end) and cancel.
 */
@Component({
  selector: 'attome-ops-maintenance',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, LocalDatePipe],
  template: `
    <section class="om-page">
      <h2>{{ 'ops.status.maintenance' | translate }}</h2>
      @if (error(); as message) { <p class="om-error" role="alert">{{ message }}</p> }
      <ul class="om-list" data-testid="om-list">
        @for (w of windows(); track w.id) {
          <li [attr.data-window]="w.id">
            <strong>{{ lang.current() === 'ar' && w.title_ar ? w.title_ar : w.title_en }}</strong>
            <span>{{ w.starts_at | localDate }}</span>
            <span>{{ w.ends_at | localDate }}</span>
            @if (w.cancelled_at) {
              <span class="om-tag">{{ 'ops.status.cancelled' | translate }}</span>
            } @else {
              <button type="button" class="om-link" [disabled]="busy()" (click)="cancel(w)" [attr.data-cancel]="w.id">{{ 'ops.status.cancelWindow' | translate }}</button>
            }
          </li>
        } @empty {
          <li>{{ 'ops.status.noMaintenance' | translate }}</li>
        }
      </ul>

      <h3>{{ 'ops.status.planWindow' | translate }}</h3>
      <div class="om-form">
        <label>{{ 'ops.status.titleEn' | translate }}<input dir="ltr" [(ngModel)]="titleEn" name="title_en" /></label>
        <label>{{ 'ops.status.titleAr' | translate }}<input dir="rtl" [(ngModel)]="titleAr" name="title_ar" /></label>
        <label>{{ 'ops.status.starts' | translate }}<input type="datetime-local" [(ngModel)]="starts" name="starts" /></label>
        <label>{{ 'ops.status.ends' | translate }}<input type="datetime-local" [(ngModel)]="ends" name="ends" /></label>
        <label>{{ 'ops.status.audience' | translate }}
          <select [(ngModel)]="audience" name="audience">
            <option value="public">{{ 'ops.status.public' | translate }}</option>
            <option value="internal">{{ 'ops.status.internal' | translate }}</option>
          </select>
        </label>
        @if (problem(); as key) { <p class="om-error" data-testid="om-problem">{{ key | translate }}</p> }
        <button type="button" data-testid="om-plan" [disabled]="busy()" (click)="plan()">{{ 'ops.status.plan' | translate }}</button>
      </div>
    </section>
  `,
  styles: [`
    .om-page { padding-inline: 1rem; max-inline-size: 48rem; display: flex; flex-direction: column; gap: 0.75rem; }
    .om-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 0.5rem; }
    .om-list li { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: center; padding-block: 0.375rem; border-block-end: 1px solid var(--color-border); }
    .om-form { display: flex; flex-direction: column; gap: 0.5rem; }
    .om-form label { display: flex; flex-direction: column; gap: 0.25rem; }
    .om-tag { font-size: 0.75rem; padding-inline: 0.375rem; border: 1px solid var(--color-border); border-radius: 0.25rem; }
    .om-link { background: none; border: 0; padding: 0; color: var(--color-accent); cursor: pointer; }
    .om-error { color: var(--color-danger); margin: 0; }
  `],
})
export class MaintenanceComponent implements OnInit {
  private readonly api = inject(ApiService);
  readonly lang = inject(LangService);

  readonly windows = signal<MaintenanceWindow[]>([]);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly problem = signal<string | null>(null);
  titleEn = '';
  titleAr = '';
  starts = '';
  ends = '';
  audience: 'public' | 'internal' = 'public';

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.api.get<{ items: MaintenanceWindow[] }>('/api/v1/ops/maintenance').subscribe({
      next: page => this.windows.set(page.items),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  plan(): void {
    const startsAt = localToIso(this.starts);
    const endsAt = localToIso(this.ends);
    const problem = windowProblem(this.titleEn, this.titleAr, startsAt, endsAt);
    this.problem.set(problem);
    if (problem) return;
    this.busy.set(true);
    this.api.post<MaintenanceWindow>('/api/v1/ops/maintenance', {
      title_en: this.titleEn.trim(),
      title_ar: this.titleAr.trim(),
      starts_at: startsAt,
      ends_at: endsAt,
      audience: this.audience,
    }).subscribe({
      next: () => {
        this.busy.set(false);
        this.titleEn = '';
        this.titleAr = '';
        this.starts = '';
        this.ends = '';
        this.load();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  cancel(window: MaintenanceWindow): void {
    this.busy.set(true);
    this.api.post<MaintenanceWindow>(`/api/v1/ops/maintenance/${encodeURIComponent(window.id)}/cancel`, {}, { ifMatch: window.row_version }).subscribe({
      next: () => {
        this.busy.set(false);
        this.load();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
