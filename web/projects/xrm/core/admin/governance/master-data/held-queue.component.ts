import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { MasterDataService, type MasterHeldContribution } from '@attome/xrm/core/admin/data';

/** The held contributions one page of the queue shows. */
export const HELD_PAGE_SIZE = 25;

/**
 * L1-T9 — the steward's held queue: contributions that failed their
 * entity's validation, newest first. Release validates the stored payload
 * again and attaches it; Reject asks for the reason and detaches it. An
 * administrator sees every master entity's, a steward only their domains'.
 * Cards, not a table, so it reads on a phone.
 */
@Component({
  selector: 'xrm-master-held-queue',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, FormsModule, TranslatePipe],
  styleUrl: './master-data.css',
  template: `
    @if (error(); as e) {
      <p class="md-error" role="alert" data-testid="held-error">{{ e }}</p>
    }
    @if (notice(); as n) {
      <p class="md-notice" role="status" data-testid="held-notice">{{ n }}</p>
    }
    @if (!loading() && items().length === 0) {
      <p class="md-hint" data-testid="held-empty">{{ 'masterData.held.empty' | translate }}</p>
    }
    <ul class="md-cards">
      @for (h of items(); track h.id) {
        <li class="md-card" data-testid="held-item" [attr.data-id]="h.id">
          <div class="md-card__head">
            <strong>{{ h.entity }}</strong>
            <span>{{ h.source_system }} · <span class="md-mono" dir="ltr">{{ h.external_id }}</span></span>
          </div>
          @if (h.held_reason) {
            <p class="md-card__reason">{{ h.held_reason }}</p>
          }
          <time class="md-item__date" [attr.datetime]="h.received_at">{{ h.received_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}</time>
          @if (rejecting() === h.id) {
            <form class="md-reject" (ngSubmit)="reject(h)">
              <label>{{ 'masterData.held.reason' | translate }}
                <input name="reason" required maxlength="1000" data-testid="held-reason"
                       [ngModel]="reason()" (ngModelChange)="reason.set($event)" />
              </label>
              <button type="submit" class="btn btn-danger btn-sm" data-testid="held-reject-confirm"
                      [disabled]="!reason().trim() || busy() === h.id">
                {{ 'masterData.held.reject' | translate }}
              </button>
              <button type="button" class="btn btn-secondary btn-sm" (click)="rejecting.set(null)">
                {{ 'masterData.cancel' | translate }}
              </button>
            </form>
          } @else {
            <div class="md-card__actions">
              <button type="button" class="btn btn-primary btn-sm" data-testid="held-release"
                      [disabled]="busy() === h.id" (click)="release(h)">
                {{ 'masterData.held.release' | translate }}
              </button>
              <button type="button" class="btn btn-secondary btn-sm" data-testid="held-reject"
                      [disabled]="busy() === h.id" (click)="startReject(h)">
                {{ 'masterData.held.reject' | translate }}
              </button>
            </div>
          }
        </li>
      }
    </ul>
    @if (total() > items().length) {
      <button type="button" class="btn btn-secondary btn-sm" data-testid="held-more" (click)="more()">
        {{ 'masterData.held.more' | translate }}
      </button>
    }
  `,
})
export class HeldQueueComponent implements OnInit {
  protected readonly lang = inject(LangService);
  private readonly svc = inject(MasterDataService);
  private readonly destroyRef = inject(DestroyRef);

  readonly items = signal<MasterHeldContribution[]>([]);
  readonly total = signal(0);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly busy = signal<string | null>(null);
  /** The contribution whose rejection reason is being typed. */
  readonly rejecting = signal<string | null>(null);
  readonly reason = signal('');
  private page = 1;

  ngOnInit(): void {
    this.fetch(1);
  }

  private fetch(page: number): void {
    this.loading.set(true);
    this.svc.held(page, HELD_PAGE_SIZE).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.page = page;
        this.items.update(list => (page === 1 ? res.items : [...list, ...res.items]));
        this.total.set(res.total);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  more(): void {
    this.fetch(this.page + 1);
  }

  private settled(h: MasterHeldContribution, key: string): void {
    this.busy.set(null);
    this.rejecting.set(null);
    this.items.update(list => list.filter(i => i.id !== h.id));
    this.total.update(t => Math.max(0, t - 1));
    this.notice.set(this.lang.translate(key, { system: h.source_system, id: h.external_id }));
  }

  private failed(e: ApiError): void {
    this.busy.set(null);
    this.error.set(e.status === 403
      ? this.lang.translate('masterData.notSteward')
      : this.lang.errorText(e));
  }

  release(h: MasterHeldContribution): void {
    this.busy.set(h.id);
    this.error.set(null);
    this.svc.release(h.entity, h.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => this.settled(h, 'masterData.held.released'),
      error: (e: ApiError) => this.failed(e),
    });
  }

  startReject(h: MasterHeldContribution): void {
    this.reason.set('');
    this.rejecting.set(h.id);
  }

  reject(h: MasterHeldContribution): void {
    const reason = this.reason().trim();
    if (!reason) return;
    this.busy.set(h.id);
    this.error.set(null);
    this.svc.reject(h.entity, h.id, reason).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => this.settled(h, 'masterData.held.rejected'),
      error: (e: ApiError) => this.failed(e),
    });
  }
}
