import { ChangeDetectionStrategy, Component, input } from '@angular/core';
import { SlaBadgeComponent } from '../sla-badge/sla-badge.component';

/**
 * The ticket list's SLA cell: `SlaBadgeComponent` behind the generic list's
 * cell-renderer contract (`EntityRouteOverride.cellRenderers`, which binds the
 * row's record data to a `row` input). Registered for the
 * `resolution_due_at` column of `service_ticket`; the ticket views select
 * the other SLA columns the badge reads (hidden) so every row carries them.
 */
@Component({
  selector:   'xrm-sla-badge-cell',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [SlaBadgeComponent],
  template:   '<xrm-sla-badge [ticket]="row()" />',
})
export class SlaBadgeCellComponent {
  /** The list row's record data. */
  readonly row = input<Record<string, unknown> | null>(null);
}
