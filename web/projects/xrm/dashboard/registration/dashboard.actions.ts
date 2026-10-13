import { inject } from '@angular/core';
import { switchMap } from 'rxjs';
import type { SelectionAction } from '@attome/xrm/core/entity';
import { EntityService } from '@attome/xrm/core/entity';
import { DashboardService } from '@attome/xrm/dashboard/data';

/**
 * "Archive selected" for the `attome_dashboard` grid (M26 Phase 2 backlog: "no
 * bulk lifecycle actions"). Calls the bespoke
 * `POST /api/v1/attome-dashboard/{id}/archive` (`attome-dashboard::lifecycle`)
 * rather than a generic entity `PATCH` — the transition needs the
 * per-dashboard advisory lock and an audit write, which the generic entity
 * API does not provide. Same shape as `grc.actions.ts`'s
 * `assessmentActions`/`findingActions`.
 *
 * Archive only, not publish: publish can 202-pend behind the D-195 four-eyes
 * gate and requires the dashboard to already be `approved`, both of which
 * make a bulk "some succeeded, some are now pending approval, some were
 * rejected outright" result genuinely ambiguous to report per-row. Archive
 * applies uniformly to any non-archived dashboard and always completes
 * synchronously, so it is the one lifecycle transition that is actually safe
 * to offer in bulk today.
 *
 * `run` reads the row's current `row_version` first — `archive`'s body
 * requires it and the grid's own row data (from the entity's default list
 * query) does not reliably carry `row_version` (same reasoning
 * `EntityService.bulkUpdate`'s doc comment gives for why *its* caller reads
 * each record first rather than trusting the list page's rows).
 */
export function dashboardActions(): SelectionAction[] {
  const dashboardApi = inject(DashboardService);
  const svc = inject(EntityService);

  return [
    {
      key: 'dashboard-archive-selected',
      labelKey: 'dashboard.archiveSelected',
      style: 'danger',
      confirmKey: 'dashboard.archiveSelectedConfirm',
      isVisible: rows => rows.some(r => r['lifecycle_status'] !== 'archived'),
      isEnabled: rows => rows.every(r => r['lifecycle_status'] !== 'archived'),
      run: id =>
        svc.get('attome_dashboard', id).pipe(
          switchMap(rec => dashboardApi.transition(id, 'archive', rec.row_version)),
        ),
    },
  ];
}
