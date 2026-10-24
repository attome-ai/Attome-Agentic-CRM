import {
  ChangeDetectionStrategy, Component, DestroyRef, effect, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { MasterDataService, type MasterSystemId } from '@attome/xrm/core/admin/data';

/**
 * L1-T9 — a golden record's contributions: each source system's id, its
 * status and when it last arrived, with Detach on an attached one (the
 * golden record is then rebuilt without it). Payloads are never shown.
 */
@Component({
  selector: 'xrm-master-contributions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  styleUrl: './master-data.css',
  template: `
    @if (error(); as e) {
      <p class="md-error" role="alert" data-testid="contributions-error">{{ e }}</p>
    }
    @if (notice(); as n) {
      <p class="md-notice" role="status" data-testid="contributions-notice">{{ n }}</p>
    }
    @if (items().length === 0 && !loading()) {
      <p class="md-hint">{{ 'masterData.contributions.empty' | translate }}</p>
    } @else {
      <ul class="md-list">
        @for (c of items(); track c.contribution_id) {
          <li class="md-item" data-testid="contribution" [attr.data-status]="c.status">
            <span class="md-item__main">
              <strong>{{ c.source_system }}</strong>
              <span class="md-mono" dir="ltr">{{ c.external_id }}</span>
            </span>
            <span [class]="'md-badge md-badge--' + c.status">{{ 'masterData.status.' + c.status | translate }}</span>
            <time class="md-item__date" [attr.datetime]="c.received_at">{{ c.received_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}</time>
            @if (c.status === 'attached') {
              <button type="button" class="btn btn-secondary btn-sm" data-testid="contribution-detach"
                      [disabled]="busy() === c.contribution_id" (click)="detach(c)">
                {{ 'masterData.contributions.detach' | translate }}
              </button>
            }
          </li>
        }
      </ul>
    }
  `,
})
export class ContributionsListComponent {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();

  protected readonly lang = inject(LangService);
  private readonly svc = inject(MasterDataService);
  private readonly destroyRef = inject(DestroyRef);

  readonly items = signal<MasterSystemId[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly busy = signal<string | null>(null);

  constructor() {
    effect(() => this.load(this.entityName(), this.recordId()));
  }

  private load(entity: string, id: string): void {
    this.loading.set(true);
    this.svc.systemIds(entity, id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: page => {
        this.items.set(page.items);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  detach(c: MasterSystemId): void {
    this.busy.set(c.contribution_id);
    this.error.set(null);
    this.svc.detach(this.entityName(), c.contribution_id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.busy.set(null);
          this.items.update(list => list.map(i =>
            i.contribution_id === c.contribution_id ? { ...i, status: 'detached' as const } : i));
          this.notice.set(this.lang.translate('masterData.contributions.detached', { system: c.source_system }));
        },
        error: (e: ApiError) => {
          this.busy.set(null);
          this.error.set(e.status === 403
            ? this.lang.translate('masterData.notSteward')
            : this.lang.errorText(e));
        },
      });
  }
}
