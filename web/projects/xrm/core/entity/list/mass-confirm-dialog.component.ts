import {
  ChangeDetectionStrategy, Component, computed, inject, input, output, signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import type { MassCondition } from './mass-condition';

export { filtersToCondition } from './mass-condition';
export type { MassCondition } from './mass-condition';

/** `attome_records::mass::MassKind`. */
export type MassKind = 'update' | 'delete' | 'reassign' | 'restore';

/** `attome_records::heavy_op::SizeEstimate`. */
export interface MassEstimate {
  exact_upto: number;
  exceeds: boolean;
  estimated_rows: number;
  estimated_seconds: number;
  path: 'inline' | 'background';
}

/** `attome_records::mass::MassRun`, as far as the list needs it. */
export interface MassRun {
  operation: { id: string; status: string; estimated_rows?: number | null; rows_done: number };
  estimate?: MassEstimate | null;
}

/** A duration in seconds as its largest whole unit. Pure. */
export function durationLabel(secs: number): string {
  const s = Math.max(0, Math.ceil(secs));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.ceil(s / 60)} min`;
  return `${Math.ceil(s / 3600)} h`;
}

/**
 * The estimate-confirm step before a mass action (roadmap AA10-T8). On
 * `show()` it asks `POST /api/v1/{entity}/mass/estimate` how many records
 * the filter selects and how long the change would take, and says when it
 * will run in the background; only then can the person confirm, and the
 * start sends the rows they were shown as `confirm_estimate_rows`, so the
 * server refuses it if the filter now selects more. Nothing starts without
 * an estimate on screen. Logical CSS only.
 */
@Component({
  selector: 'xrm-mass-confirm-dialog',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    @if (open()) {
    <div class="mc-backdrop" role="presentation" (click)="close()">
      <!-- eslint-disable-next-line @angular-eslint/template/click-events-have-key-events -->
      <section class="mc-dialog" role="dialog" aria-modal="true"
        [attr.aria-label]="('massConfirm.title.' + kind()) | translate" (click)="$event.stopPropagation()">
        <h3>{{ ('massConfirm.title.' + kind()) | translate }}</h3>
        @if (error(); as message) { <p class="mc-error" role="alert">{{ message }}</p> }
        @if (estimate(); as e) {
          <p data-estimate-rows>
            {{ (e.exceeds ? 'massConfirm.rowsAbout' : 'massConfirm.rowsExact') | translate: { count: e.estimated_rows } }}
          </p>
          <p data-estimate-time>{{ 'massConfirm.time' | translate: { time: duration(e.estimated_seconds) } }}</p>
          @if (e.path === 'background') {
            <p class="mc-note" data-background-note>{{ 'massConfirm.background' | translate }}</p>
          }
          <label class="mc-reason">
            <span>{{ 'massConfirm.reason' | translate }}</span>
            <textarea rows="2" [ngModel]="reason()" (ngModelChange)="reason.set($event)" [disabled]="starting()"></textarea>
          </label>
        } @else if (!error()) {
          <p>{{ 'massConfirm.estimating' | translate }}</p>
        }
        <footer>
          <button type="button" class="mc-cancel" [disabled]="starting()" (click)="close()">{{ 'massConfirm.cancel' | translate }}</button>
          <button type="button" class="mc-confirm" data-confirm [disabled]="!canStart()" (click)="start()">
            {{ ('massConfirm.confirm.' + kind()) | translate }}
          </button>
        </footer>
      </section>
    </div>
    }
  `,
  styles: [`
    .mc-backdrop { position: fixed; inset: 0; background: var(--color-overlay, #0f172a73); display: grid; place-items: center; z-index: 1000; }
    .mc-dialog { background: var(--surface, #ffffff); color: inherit; border-radius: 0.8rem; padding-block: 1.25rem; padding-inline: 1.5rem; inline-size: min(32rem, 92vw); }
    .mc-note { padding-block: 0.5rem; padding-inline: 0.75rem; border-inline-start: 3px solid var(--primary, #2563eb); background: var(--surface-muted, #f1f5f9); }
    .mc-reason { display: grid; gap: 0.3rem; margin-block: 0.75rem; }
    .mc-error { color: var(--danger, #b91c1c); }
    footer { display: flex; justify-content: flex-end; gap: 0.5rem; margin-block-start: 1rem; }
  `],
})
export class MassConfirmDialogComponent {
  private readonly api = inject(ApiService);

  readonly entity = input.required<string>();
  readonly kind = input<MassKind>('delete');
  /** `null`: every record. */
  readonly filter = input<MassCondition | null>(null);
  readonly payload = input<Record<string, unknown>>({});

  /** The operation started, inline or in the background. */
  readonly started = output<MassRun>();

  readonly open = signal(false);
  readonly estimate = signal<MassEstimate | null>(null);
  readonly error = signal<string | null>(null);
  readonly starting = signal(false);
  readonly reason = signal('');
  readonly canStart = computed(() => this.estimate() !== null && !this.starting());

  readonly duration = durationLabel;

  show(): void {
    this.open.set(true);
    this.estimate.set(null);
    this.error.set(null);
    this.reason.set('');
    this.api.post<MassEstimate>(`/api/v1/${this.entity()}/mass/estimate`, this.body()).subscribe({
      next: estimate => this.estimate.set(estimate),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  close(): void {
    if (this.starting()) return;
    this.open.set(false);
  }

  start(): void {
    const estimate = this.estimate();
    if (!estimate || this.starting()) return;
    this.starting.set(true);
    this.error.set(null);
    const reason = this.reason().trim();
    this.api.post<MassRun>(`/api/v1/${this.entity()}/mass`, {
      ...this.body(),
      reason: reason || undefined,
      confirm_estimate_rows: estimate.estimated_rows,
    }).subscribe({
      next: run => {
        this.starting.set(false);
        this.open.set(false);
        this.started.emit(run);
      },
      error: (e: ApiError) => {
        this.starting.set(false);
        this.error.set(e.message);
      },
    });
  }

  private body(): { kind: MassKind; filter: MassCondition | null; payload: Record<string, unknown> } {
    return { kind: this.kind(), filter: this.filter(), payload: this.payload() };
  }
}
