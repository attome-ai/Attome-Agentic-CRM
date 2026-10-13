import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { DuplicateCandidate, DuplicatesService } from '@attome/xrm/core/admin/data';
import { entityFormRoute } from '../services/entity-url.utils';

/**
 * D-432 / M13 (Master Data Management, scoped to dedup + survivorship only)
 * — the record form's "possible duplicate" banner. Renders nothing until
 * `GET /api/v1/data/duplicates/for-record` returns at least one open
 * candidate touching this record — no `Admin` gate server-side (only the
 * caller's own read access to the record), so this is safe to show on every
 * form, not only for admins.
 *
 * `recordId` is `null` on a not-yet-saved (create-mode) record — there is
 * nothing to look up yet, so this renders nothing until the id input flips
 * to a real value (`EntityFormComponent` passes its own `id()` straight
 * through, which does exactly that on first save).
 */
@Component({
  selector: 'xrm-duplicate-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  styleUrls: ['./duplicate-banner.component.css'],
  templateUrl: './duplicate-banner.component.html',
})
export class DuplicateBannerComponent {
  private readonly svc = inject(DuplicatesService);

  readonly entity = input.required<string>();
  readonly recordId = input<string | null>(null);

  readonly candidates = signal<DuplicateCandidate[]>([]);
  readonly dismissed = signal(false);
  readonly formRoute = computed(() => entityFormRoute(this.entity()));

  constructor() {
    effect(() => {
      const entity = this.entity();
      const recordId = this.recordId();
      this.dismissed.set(false);
      if (!recordId) {
        this.candidates.set([]);
        return;
      }
      // Best-effort: a lookup failure (e.g. the caller can't read the
      // record for some reason `require_record_access` catches that this
      // form itself already got past) just hides the banner rather than
      // surfacing a second error state on top of the form's own.
      this.svc.candidatesForRecord(entity, recordId).subscribe({
        next: items => this.candidates.set(items),
        error: () => this.candidates.set([]),
      });
    });
  }

  otherRecordId(c: DuplicateCandidate): string {
    return c.record_a === this.recordId() ? c.record_b : c.record_a;
  }

  scorePercent(c: DuplicateCandidate): string {
    return `${Math.round(c.score * 100)}%`;
  }
}
