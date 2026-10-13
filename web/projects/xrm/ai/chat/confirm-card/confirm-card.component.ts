import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, output, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { ChatService } from '../services/chat.service';
import type { ToolCallView } from '../services/chat.service';
import { summarizeProposal, wantsCurrentRecord } from '../proposal-diff';

/** What happened when the user acted on the card. */
export type ConfirmCardResult =
  | { kind: 'executed' }
  | { kind: 'approval_requested'; approvalRequestId: string }
  | { kind: 'rejected' }
  | { kind: 'refused'; message: string };

/**
 * A confirmation card for one **server-persisted** proposal (I-13).
 *
 * It shows the stored `arguments` — and, for an edit of an existing record, the
 * record's current values beside them, read as the user through the ordinary
 * entity API. Both are display only. Confirming sends the proposal's
 * `arguments_hash` and nothing else (`ChatService.confirm` cannot carry more,
 * row A-08); the arguments that run are the server's stored copy.
 */
@Component({
  selector: 'attome-ai-confirm-card',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./confirm-card.component.css'],
  templateUrl: './confirm-card.component.html',
})
export class ConfirmCardComponent implements OnInit {
  private readonly chat = inject(ChatService);
  private readonly destroyRef = inject(DestroyRef);

  readonly conversationId = input.required<string>();
  readonly toolCall = input.required<ToolCallView>();
  readonly resolved = output<ConfirmCardResult>();

  readonly current = signal<Record<string, unknown> | null>(null);
  /** Set when the current record could not be read — the card still works, without a diff. */
  readonly currentUnavailable = signal(false);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  readonly summary = computed(() =>
    summarizeProposal(this.toolCall().action_id, this.toolCall().arguments, this.current()),
  );
  readonly showsCurrent = computed(() => this.current() !== null);

  ngOnInit(): void {
    const call = this.toolCall();
    const { entity, recordId } = summarizeProposal(call.action_id, call.arguments, null);
    if (!wantsCurrentRecord(call.action_id) || !entity || !recordId) return;
    this.chat
      .currentRecord(entity, recordId)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (data) => this.current.set(data),
        // Refused or missing: show the proposed values alone. The read is the
        // user's own, so a refusal here means they may not see the record.
        error: () => this.currentUnavailable.set(true),
      });
  }

  confirm(): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    const call = this.toolCall();
    this.chat
      .confirm(this.conversationId(), call.tool_call_id, call.arguments_hash)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (result) => {
          this.busy.set(false);
          this.resolved.emit(
            result.outcome === 'approval_requested' && 'approval_request_id' in result
              ? { kind: 'approval_requested', approvalRequestId: result.approval_request_id }
              : { kind: 'executed' },
          );
        },
        error: (err: ApiError) => {
          this.busy.set(false);
          this.error.set(err.message);
          this.resolved.emit({ kind: 'refused', message: err.message });
        },
      });
  }

  reject(): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.chat
      .reject(this.conversationId(), this.toolCall().tool_call_id)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: () => {
          this.busy.set(false);
          this.resolved.emit({ kind: 'rejected' });
        },
        error: (err: ApiError) => {
          this.busy.set(false);
          this.error.set(err.message);
          this.resolved.emit({ kind: 'refused', message: err.message });
        },
      });
  }
}
