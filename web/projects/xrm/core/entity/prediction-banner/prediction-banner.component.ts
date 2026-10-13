import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { Prediction, PredictionsService } from '@attome/xrm/core/admin/data';

/**
 * M36 Phase 0+1 (Predictive Intelligence, D-473) — the record form's
 * "prediction" banner, same shape/precedent as `DuplicateBannerComponent`:
 * renders nothing until `GET /api/v1/predictions?regarding_entity=&
 * regarding_id=` returns at least one prediction for this record. No
 * `Admin` gate server-side (only the caller's own `{entity}.read`), so this
 * is safe to mount on every entity's form — Phase 1 only ever writes
 * predictions for `service_ticket`, so it renders nothing on every other
 * entity's form today, exactly as `entity_data_grid`/other generic surfaces
 * already do for entities they have no data for.
 *
 * `recordId` is `null` on a not-yet-saved (create-mode) record — same
 * "nothing to look up yet" posture `DuplicateBannerComponent` takes.
 */
@Component({
  selector: 'xrm-prediction-banner',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./prediction-banner.component.css'],
  templateUrl: './prediction-banner.component.html',
})
export class PredictionBannerComponent {
  private readonly svc = inject(PredictionsService);

  readonly entity = input.required<string>();
  readonly recordId = input<string | null>(null);

  readonly predictions = signal<Prediction[]>([]);
  readonly dismissed = signal(false);

  /** The single most recent prediction — the banner shows one score, not a
   *  history (a per-record detail view is future work, same scope cut
   *  `DuplicateBannerComponent`'s own list-of-candidates keeps simple). */
  readonly latest = computed<Prediction | null>(() => this.predictions()[0] ?? null);

  readonly scorePercent = computed(() => {
    const p = this.latest();
    return p ? `${Math.round(p.score * 100)}%` : '';
  });

  readonly topContributions = computed(() => {
    const p = this.latest();
    return (p?.explanation ?? []).slice(0, 3);
  });

  constructor() {
    effect(() => {
      const entity = this.entity();
      const recordId = this.recordId();
      this.dismissed.set(false);
      if (!recordId) {
        this.predictions.set([]);
        return;
      }
      // Best-effort: a lookup failure (e.g. an entity this build never
      // scores, or a transient error) just hides the banner rather than
      // surfacing a second error state on top of the form's own — same
      // posture `DuplicateBannerComponent` takes.
      this.svc.forRecord(entity, recordId, 1).subscribe({
        next: page => this.predictions.set(page.items),
        error: () => this.predictions.set([]),
      });
    });
  }
}
