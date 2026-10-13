import { inject } from '@angular/core';
import { map } from 'rxjs';
import { ApiService } from '@attome/base';
import type { SelectionAction } from '@attome/xrm/core/entity';

interface TestConnectionResponse {
  ok:     boolean;
  detail: string | null;
}

/**
 * "Test connection" for the `integration_system` grid (M59 Phase 1) —
 * calls the bespoke `POST /api/v1/admin/integrations/systems/{id}/
 * test-connection` (SSRF-guarded, dial-time, `attome-integration/src/admin.rs`)
 * rather than anything generic: the generic entity API has no notion of
 * "reach out to this row's `base_url` and report back."
 *
 * Deliberately a single-row-only action (`isVisible`/`isEnabled` both
 * require exactly one selected row) — the probe result is reported per
 * system, and fanning it out over a multi-row selection would mean either a
 * confusing merged result or N alerts in a row. `SelectionAction.run` is
 * still per-id (the list component fans out over the selection itself), so
 * this restriction is purely the visibility/enablement predicate, not a
 * different call shape.
 */
export function integrationSystemActions(): SelectionAction[] {
  const api = inject(ApiService);

  return [
    {
      key:       'integration-test-connection',
      labelKey:  'integration.testConnection',
      style:     'secondary',
      isVisible: rows => rows.length === 1,
      isEnabled: rows => rows.length === 1,
      run: id =>
        api
          .post<TestConnectionResponse>(`/api/v1/admin/integrations/systems/${id}/test-connection`, {})
          .pipe(
            map(result => {
              // The grid's action runner only cares that the observable
              // completed — surfacing the human-readable outcome is a plain
              // alert for now (Phase 1 scope; a toast/inline status chip is
              // a Phase 2 UI polish item, not a functional gap).
              const message = result.ok
                ? 'Connection succeeded.'
                : `Connection failed: ${result.detail ?? 'unknown error'}`;
              alert(message);
              return result;
            }),
          ),
    },
  ];
}
