import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiError } from '@attome/base';
import { DuplicateCandidate, DuplicatesService } from '@attome/xrm/core/admin/data';

/**
 * D-432 / M13 (Master Data Management, scoped to dedup + survivorship only)
 * — the steward queue: lists `duplicate_candidate` rows the
 * matching job (`EngineJob::DataMatchSweep`) wrote, and lets an admin
 * either merge a pair (picking which record survives) or dismiss it as not
 * actually a duplicate. Written by hand against `approval-queue-list.
 * component.ts`'s and `failed-jobs-list.component.ts`'s conventions (inline
 * signals, shared `admin-page.css`, `ApiError` handling).
 *
 * Candidate rows carry only the two records' raw ids — this generic surface
 * has no reliable per-entity "display name" to join in (a field the entity
 * happens to call `name` is a convention, not every entity's metadata
 * declares a `primary_name_attribute`), so a steward reviewing a pair may
 * need to open both records in a second tab to compare them before merging.
 */
@Component({
  selector: 'xrm-duplicates-manager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, FormsModule],
  styleUrls: ['../../../styles/admin-page.css', './duplicates-manager.component.css'],
  templateUrl: './duplicates-manager.component.html',
})
export class DuplicatesManagerComponent implements OnInit {
  private readonly svc = inject(DuplicatesService);

  readonly items = signal<DuplicateCandidate[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly busyId = signal<string | null>(null);
  readonly entityFilter = signal('');

  /** Which record the steward has picked as canonical for the currently
   *  open merge confirmation, keyed by candidate id. */
  readonly canonicalChoice = signal<Record<string, string>>({});
  readonly mergingId = signal<string | null>(null);
  readonly dismissingId = signal<string | null>(null);
  readonly dismissNote = signal('');
  readonly conflictsById = signal<Record<string, string[]>>({});

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    const entity = this.entityFilter().trim() || undefined;
    this.svc.listCandidates(1, 50, 'open', entity).subscribe({
      next: res => { this.items.set(res.items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  pickCanonical(candidateId: string, recordId: string): void {
    this.canonicalChoice.update(m => ({ ...m, [candidateId]: recordId }));
  }

  toggleMerge(c: DuplicateCandidate): void {
    if (this.mergingId() === c.id) {
      this.mergingId.set(null);
    } else {
      this.mergingId.set(c.id);
      this.dismissingId.set(null);
      // Default to `record_a` so the confirm button is never accidentally
      // disabled by an unset choice — the steward can still change it.
      if (!this.canonicalChoice()[c.id]) this.pickCanonical(c.id, c.record_a);
    }
  }

  confirmMerge(c: DuplicateCandidate): void {
    const canonicalId = this.canonicalChoice()[c.id];
    if (!canonicalId) return;
    this.busyId.set(c.id);
    this.svc.mergeCandidate(c.id, canonicalId).subscribe({
      next: res => {
        this.busyId.set(null);
        this.mergingId.set(null);
        if (res.survivorship_conflicts?.length) {
          this.conflictsById.update(m => ({ ...m, [c.id]: res.survivorship_conflicts }));
        }
        this.load();
      },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
    });
  }

  toggleDismiss(c: DuplicateCandidate): void {
    if (this.dismissingId() === c.id) {
      this.dismissingId.set(null);
    } else {
      this.dismissingId.set(c.id);
      this.mergingId.set(null);
      this.dismissNote.set('');
    }
  }

  confirmDismiss(c: DuplicateCandidate): void {
    this.busyId.set(c.id);
    this.svc.dismissCandidate(c.id, c.row_version, this.dismissNote().trim() || undefined).subscribe({
      next: () => { this.busyId.set(null); this.dismissingId.set(null); this.load(); },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
    });
  }

  scorePercent(c: DuplicateCandidate): string {
    return `${Math.round(c.score * 100)}%`;
  }
}
