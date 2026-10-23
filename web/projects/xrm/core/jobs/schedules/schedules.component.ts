import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_api::schedules_admin::ScheduleItem`. */
export interface ScheduleItem {
  kind: 'flow' | 'report' | 'platform';
  id: string;
  name: string;
  owner: string | null;
  schedule: string;
  next_run_at: string | null;
  last_run_at: string | null;
  last_result: string | null;
  paused: boolean;
  can_pause: boolean;
}

/** One quiet window, `HH:MM` in the deployment's time. */
export interface QuietWindow { start: string; end: string }

interface Page<T> { items: T[]; total: number }
interface SettingRow { key: string; value: unknown }

const QUIET_KEY = 'jobs.quiet_windows';
const KINDS = ['all', 'flow', 'report', 'platform'] as const;
type Kind = (typeof KINDS)[number];
const TIME = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

/** The windows a setting value holds, ignoring malformed entries. */
export function quietWindowsOf(value: unknown): QuietWindow[] {
  if (!Array.isArray(value)) return [];
  return value.filter((w): w is QuietWindow =>
    typeof w === 'object' && w !== null
    && typeof (w as QuietWindow).start === 'string' && TIME.test((w as QuietWindow).start)
    && typeof (w as QuietWindow).end === 'string' && TIME.test((w as QuietWindow).end));
}

/**
 * Every schedule in one place (roadmap M12-T3): flow schedules, report
 * deliveries and the platform's own schedulers (read-only), each with its
 * next and last run and owner. Flow and report schedules pause and resume
 * here (audited). The quiet windows heavy scheduled work waits out are
 * edited below the list (`jobs.quiet_windows`). Logical CSS only.
 */
@Component({
  selector: 'xrm-schedules',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, LocalDatePipe, TranslatePipe],
  template: `
    <section class="sc">
      <div class="sc-head">
        <h3>{{ 'schedules.title' | translate }}</h3>
        <button type="button" (click)="load()" [disabled]="busy()">{{ 'schedules.refresh' | translate }}</button>
      </div>
      @if (error(); as message) { <p class="sc-error" role="alert">{{ message }}</p> }
      <div class="sc-filters" role="group" [attr.aria-label]="'schedules.kind' | translate">
        @for (k of kinds; track k) {
          <button type="button" [class.sc-on]="kind() === k" [attr.aria-pressed]="kind() === k" (click)="kind.set(k)">
            {{ 'schedules.kinds.' + k | translate }}
          </button>
        }
      </div>
      @if (shown().length === 0) {
        <p class="sc-muted">{{ 'schedules.none' | translate }}</p>
      } @else {
        <table class="sc-table">
          <thead>
            <tr>
              <th scope="col">{{ 'schedules.name' | translate }}</th>
              <th scope="col">{{ 'schedules.schedule' | translate }}</th>
              <th scope="col">{{ 'schedules.nextRun' | translate }}</th>
              <th scope="col">{{ 'schedules.lastRun' | translate }}</th>
              <th scope="col">{{ 'schedules.owner' | translate }}</th>
              <th scope="col"><span class="sc-sr">{{ 'schedules.actions' | translate }}</span></th>
            </tr>
          </thead>
          <tbody>
            @for (s of shown(); track s.kind + s.id) {
              <tr [attr.data-schedule]="s.kind + ':' + s.id" [class.sc-paused]="s.paused">
                <td>
                  {{ s.name }}
                  <span class="sc-kind">{{ 'schedules.kinds.' + s.kind | translate }}</span>
                </td>
                <td dir="ltr"><code>{{ s.schedule }}</code></td>
                <td>
                  @if (s.paused) { {{ 'schedules.paused' | translate }} }
                  @else if (s.next_run_at) { {{ s.next_run_at | localDate }} }
                  @else { — }
                </td>
                <td>
                  @if (s.last_run_at) { {{ s.last_run_at | localDate }} } @else { — }
                  @if (s.last_result) { <span class="sc-result">{{ 'schedules.result.' + s.last_result | translate }}</span> }
                </td>
                <td>{{ s.owner ?? '—' }}</td>
                <td>
                  @if (s.can_pause) {
                    @if (s.paused) {
                      <button type="button" class="sc-resume" (click)="setPaused(s, false)" [disabled]="busy()">{{ 'schedules.resume' | translate }}</button>
                    } @else {
                      <button type="button" class="sc-pause" (click)="setPaused(s, true)" [disabled]="busy()">{{ 'schedules.pause' | translate }}</button>
                    }
                  } @else {
                    <span class="sc-muted">{{ 'schedules.readOnly' | translate }}</span>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      }

      <h4>{{ 'schedules.quiet.title' | translate }}</h4>
      <p class="sc-muted">{{ 'schedules.quiet.intro' | translate }}</p>
      @for (w of windows(); track $index) {
        <div class="sc-window">
          <label>{{ 'schedules.quiet.start' | translate }} <input type="time" [(ngModel)]="w.start" /></label>
          <label>{{ 'schedules.quiet.end' | translate }} <input type="time" [(ngModel)]="w.end" /></label>
          <button type="button" (click)="removeWindow($index)">{{ 'schedules.quiet.remove' | translate }}</button>
        </div>
      }
      <div class="sc-buttons">
        <button type="button" (click)="addWindow()">{{ 'schedules.quiet.add' | translate }}</button>
        <button type="button" class="sc-save" (click)="saveWindows()" [disabled]="busy()">{{ 'schedules.quiet.save' | translate }}</button>
      </div>
      @if (notice(); as message) { <p class="sc-muted" role="status">{{ message | translate }}</p> }
    </section>
  `,
  styles: [`
    :host { display: block; }
    .sc { display: flex; flex-direction: column; gap: 0.5rem; }
    .sc-head { display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; }
    .sc h3, .sc h4 { margin-block: 0; font-size: 1rem; }
    .sc h4 { margin-block-start: 1rem; }
    .sc-filters, .sc-buttons, .sc-window { display: flex; flex-wrap: wrap; gap: 0.375rem; align-items: center; }
    .sc-on { font-weight: 600; }
    .sc-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .sc-table th, .sc-table td { text-align: start; padding-block: 0.25rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .sc-paused td { color: var(--color-text-secondary); }
    .sc-kind, .sc-result { display: block; font-size: 0.75rem; color: var(--color-text-secondary); }
    .sc-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
    .sc-error { color: var(--color-danger); }
    .sc-sr { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
  `],
})
export class SchedulesComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly kinds = KINDS;
  readonly items = signal<ScheduleItem[]>([]);
  readonly kind = signal<Kind>('all');
  readonly shown = computed(() => {
    const kind = this.kind();
    return kind === 'all' ? this.items() : this.items().filter(s => s.kind === kind);
  });
  readonly windows = signal<QuietWindow[]>([]);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly busy = signal(false);

  ngOnInit(): void {
    this.load();
  }

  load(): void {
    this.error.set(null);
    this.api.get<Page<ScheduleItem>>('/api/v1/admin/schedules').subscribe({
      next: page => this.items.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.api.get<{ items: SettingRow[] }>('/api/v1/admin/settings').subscribe({
      next: list => this.windows.set(
        quietWindowsOf(list.items.find(s => s.key === QUIET_KEY)?.value).map(w => ({ ...w })),
      ),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  setPaused(item: ScheduleItem, paused: boolean): void {
    this.busy.set(true);
    const action = paused ? 'pause' : 'resume';
    this.api.post<unknown>(
      `/api/v1/admin/schedules/${encodeURIComponent(item.kind)}/${encodeURIComponent(item.id)}/${action}`, {},
    ).subscribe({
      next: () => {
        this.busy.set(false);
        this.items.update(all => all.map(s => s.kind === item.kind && s.id === item.id ? { ...s, paused } : s));
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  addWindow(): void {
    this.windows.update(all => [...all, { start: '08:00', end: '18:00' }]);
  }

  removeWindow(index: number): void {
    this.windows.update(all => all.filter((_, i) => i !== index));
  }

  saveWindows(): void {
    const value = quietWindowsOf(this.windows()).filter(w => w.start !== w.end);
    this.busy.set(true);
    this.notice.set(null);
    this.api.put<unknown>(`/api/v1/admin/settings/${QUIET_KEY}`, { scope: 'deployment', scope_ref: null, value })
      .subscribe({
        next: () => { this.busy.set(false); this.windows.set(value); this.notice.set('schedules.quiet.saved'); },
        error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
      });
  }
}
