import { Routes } from '@angular/router';

/**
 * The operations pages under `/xrm/ops/**` (AB4-T1); the host mounts the
 * lazy chunk. The server answers each page's API only with the `ops`
 * module on.
 */
export const OPS_ROUTES: Routes = [
  // AB2-T11: the database cluster and planned switchover.
  {
    path: 'cluster',
    loadComponent: () => import('./cluster/cluster-status.component').then(m => m.ClusterStatusComponent),
  },
  // AB4-T11: recovery drills, their schedules and the auditor pack.
  {
    path: 'drills',
    loadComponent: () => import('./drills/drill-history.component').then(m => m.DrillHistoryComponent),
  },
  {
    path: 'drills/:id',
    loadComponent: () => import('./drills/drill-detail.component').then(m => m.DrillDetailComponent),
  },
];
