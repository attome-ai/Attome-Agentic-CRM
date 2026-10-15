import { ChangeDetectionStrategy, Component, computed, effect, inject, input, output, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { TranslatePipe } from '@attome/base';
import { DuplicateCandidate, DuplicatesService, MergeResponse } from '@attome/xrm/core/admin/data';
import { MergeDialogComponent } from '../merge-dialog/merge-dialog.component';
import { MergeUndoBarComponent } from '../merge-dialog/merge-undo-bar.component';
import { entityFormRoute } from '../services/entity-url.utils';
import { DuplicateNotice } from './duplicate-notice';

/**
 * D-432 / M13 — the record form's duplicate banner, in two parts.
 *
 * 1. A15-T4: what the last save found (`notice`). A refused save lists the
 *    records it matches (links), says how many more exist that the person
 *    cannot see, and, when the rule is `allow_with_reason`, asks for the
 *    reason and saves again with it (`Attome-Duplicate-Reason`). A save that
 *    went through under a `warn` rule lists the same.
 * 2. The open candidates the sweep found for this record
 *    (`GET /api/v1/data/duplicates/for-record`; no admin gate, only read
 *    access to the record), each with a Merge button that opens the
 *    side-by-side merge dialog (A15-T10). Nothing shows until the record is
 *    saved (`recordId` is `null` on a create form).
 */
@Component({
  selector: 'xrm-duplicate-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe, MergeDialogComponent, MergeUndoBarComponent],
  styleUrls: ['../../../styles/inline-actions.css', './duplicate-banner.component.css'],
  templateUrl: './duplicate-banner.component.html',
})
export class DuplicateBannerComponent {
  private readonly svc = inject(DuplicatesService);

  readonly entity = input.required<string>();
  readonly recordId = input<string | null>(null);
  /** A15-T4: the last save's duplicate refusal or warning. */
  readonly notice = input<DuplicateNotice | null>(null);
  /** The person gave the reason an `allow_with_reason` rule asks for. */
  readonly saveWithReason = output<string>();
  /** A merge (or its undo) changed the open record; the form reloads it. */
  readonly changed = output<void>();

  readonly candidates = signal<DuplicateCandidate[]>([]);
  readonly dismissed = signal(false);
  readonly reason = signal('');
  /** The candidate whose merge dialog is open. */
  readonly merging = signal<DuplicateCandidate | null>(null);
  /** The last merge made here, for its Undo bar. */
  readonly lastMergeId = signal<string | null>(null);
  readonly formRoute = computed(() => entityFormRoute(this.entity()));

  constructor() {
    effect(() => {
      const entity = this.entity();
      const recordId = this.recordId();
      this.dismissed.set(false);
      this.merging.set(null);
      if (!recordId) {
        this.candidates.set([]);
        return;
      }
      this.loadCandidates(entity, recordId);
    });
    // A new notice asks for a new reason.
    effect(() => {
      this.notice();
      this.reason.set('');
    });
  }

  private loadCandidates(entity: string, recordId: string): void {
    // Best-effort: a lookup failure just hides the list rather than adding a
    // second error state on top of the form's own.
    this.svc.candidatesForRecord(entity, recordId).subscribe({
      next: items => this.candidates.set(items),
      error: () => this.candidates.set([]),
    });
  }

  otherRecordId(c: DuplicateCandidate): string {
    return c.record_a === this.recordId() ? c.record_b : c.record_a;
  }

  percent(score: number): string {
    return `${Math.round(score * 100)}%`;
  }

  submitReason(): void {
    const reason = this.reason().trim();
    if (reason) this.saveWithReason.emit(reason);
  }

  onMerged(result: MergeResponse): void {
    this.merging.set(null);
    this.lastMergeId.set(result.merge_log_id);
    this.changed.emit();
    this.refresh();
  }

  onUndone(): void {
    this.lastMergeId.set(null);
    this.changed.emit();
    this.refresh();
  }

  private refresh(): void {
    const id = this.recordId();
    if (id) this.loadCandidates(this.entity(), id);
  }
}
