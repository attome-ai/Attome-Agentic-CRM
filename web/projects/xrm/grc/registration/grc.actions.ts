import { inject } from '@angular/core';
import { map } from 'rxjs';
import { ApiService } from '@attome/base';
import type { SelectionAction } from '@attome/xrm/core/entity';

interface AssessmentStartResponse {
  id:         string;
  status:     string;
  started_at: string;
}

interface FindingRemediateResponse {
  id:            string;
  status:        string;
  remediated_at: string;
}

/**
 * "Start" for the `grc_assessment` grid (M20-grc.md Phase 1 checklist) —
 * calls the bespoke `POST /api/v1/grc/assessments/{id}/start`
 * (`attome-grc/src/lifecycle.rs`) rather than a generic entity `PATCH`: the
 * transition needs a same-record advisory lock and an audit write, which the
 * generic entity API does not provide. Same shape
 * `integrationSystemActions`'s "Test connection" uses.
 *
 * Single-row-only, same reasoning as that action: the result (started, or
 * already past `planned`) is reported per assessment.
 */
export function assessmentActions(): SelectionAction[] {
  const api = inject(ApiService);

  return [
    {
      key: 'grc-assessment-start',
      labelKey: 'grc.assessment.start',
      style: 'primary',
      isVisible: rows => rows.length === 1,
      isEnabled: rows => rows.length === 1 && rows[0]?.['status'] === 'planned',
      run: id =>
        api
          .post<AssessmentStartResponse>(`/api/v1/grc/assessments/${id}/start`, {})
          .pipe(map(result => result)),
    },
  ];
}

/**
 * "Remediate" for the `grc_finding` grid — calls the bespoke
 * `POST /api/v1/grc/findings/{id}/remediate`. Same shape as
 * [`assessmentActions`] above.
 */
export function findingActions(): SelectionAction[] {
  const api = inject(ApiService);

  return [
    {
      key: 'grc-finding-remediate',
      labelKey: 'grc.finding.remediate',
      style: 'primary',
      isVisible: rows => rows.length === 1,
      isEnabled: rows =>
        rows.length === 1 &&
        ['open', 'in_progress'].includes(String(rows[0]?.['status'] ?? '')),
      run: id =>
        api
          .post<FindingRemediateResponse>(`/api/v1/grc/findings/${id}/remediate`, {})
          .pipe(map(result => result)),
    },
  ];
}
