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
  // AB3-T10: recovery targets, the live recovery point, the runbook and
  // declared disasters.
  {
    path: 'recovery',
    loadComponent: () => import('./recovery/recovery.component').then(m => m.RecoveryComponent),
  },
  // AB4-T11: recovery drills, their schedules and the auditor pack.
  {
    path: 'drills',
    loadComponent: () => import('./drills/drill-history.component').then(m => m.DrillHistoryComponent),
  },
  // AB11-T9: incidents and planned maintenance on the status page.
  {
    path: 'incidents',
    loadComponent: () => import('./incidents/incidents.component').then(m => m.IncidentsComponent),
  },
  {
    path: 'maintenance',
    loadComponent: () => import('./incidents/maintenance.component').then(m => m.MaintenanceComponent),
  },
  {
    path: 'drills/:id',
    loadComponent: () => import('./drills/drill-detail.component').then(m => m.DrillDetailComponent),
  },
];
