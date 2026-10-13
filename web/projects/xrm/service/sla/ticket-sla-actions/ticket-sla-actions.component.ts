import { ChangeDetectionStrategy, Component, computed, inject, input, output, signal } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { SLA_PAUSE_REASONS, SlaPauseReason, SlaService } from '../sla.service';

export type SlaAction = 'apply' | 'pause' | 'resume' | 'recalculate';

/**
 * The ticket form's SLA actions (U14): apply the matching policy, pause or
 * resume the SLA clock, and recalculate an unresolved SLA. Each succeeds or
 * fails visibly — a 403 (no `service_ticket.update`), a 409 (another
 * pause/resume in flight) and a 404 each get their own message, never a
 * silent no-op.
 *
 * `locked` disables every action while the form has unsaved edits: the
 * actions change the ticket server-side and the form then reloads the record
 * (`changed`), which would otherwise discard the operator's edits — or, left
 * unreloaded, turn their next save into a version conflict.
 */
@Component({
  selector: 'xrm-ticket-sla-actions',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./ticket-sla-actions.component.css'],
  templateUrl: './ticket-sla-actions.component.html',
})
export class TicketSlaActionsComponent {
  readonly ticketId = input.required<string>();
  readonly locked   = input(false);
  /** Emitted after any action succeeds, so the host re-reads the ticket. */
  readonly changed  = output<SlaAction>();

  private readonly sla  = inject(SlaService);
  private readonly lang = inject(LangService);

  readonly pauseReasons = SLA_PAUSE_REASONS;
  readonly pauseReason  = signal<SlaPauseReason>('waiting_customer');
  readonly busy   = signal<SlaAction | null>(null);
  readonly error  = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly disabled = computed(() => this.locked() || this.busy() !== null);

  onReasonChange(event: Event): void {
    this.pauseReason.set((event.target as HTMLSelectElement).value as SlaPauseReason);
  }

  apply(): void {
    this.run('apply', this.sla.applyPolicy(this.ticketId()), res =>
      res ? 'serviceSla.notice.applied' : 'serviceSla.notice.noPolicy');
  }

  pause(): void {
    this.run('pause', this.sla.pauseClock(this.ticketId(), this.pauseReason()), () => 'serviceSla.notice.paused');
  }

  resume(): void {
    this.run('resume', this.sla.resumeClock(this.ticketId()), () => 'serviceSla.notice.resumed');
  }

  recalculate(): void {
    this.run('recalculate', this.sla.recalculate(this.ticketId()), res =>
      res.recalculated ? 'serviceSla.notice.recalculated' : 'serviceSla.notice.nothingToRecalculate');
  }

  private run<T>(action: SlaAction, req$: Observable<T>, noticeKey: (res: T) => string): void {
    if (this.disabled()) return;
    this.busy.set(action);
    this.error.set(null);
    this.notice.set(null);
    req$.subscribe({
      next: res => {
        this.busy.set(null);
        this.notice.set(this.lang.translate(noticeKey(res)));
        this.changed.emit(action);
      },
      error: (e: ApiError) => {
        this.busy.set(null);
        this.error.set(this.errorText(e));
      },
    });
  }

  private errorText(e: ApiError): string {
    switch (e.kind) {
      case 'forbidden':        return this.lang.translate('serviceSla.error.forbidden');
      case 'conflict':
      case 'version_conflict': return this.lang.translate('serviceSla.error.conflict');
      case 'not_found':        return this.lang.translate('serviceSla.error.notFound');
      default:                 return e.message || this.lang.translate('serviceSla.error.failed');
    }
  }
}
