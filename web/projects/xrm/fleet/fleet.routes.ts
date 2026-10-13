import { Routes } from '@angular/router';
import { FleetDeploymentDetailComponent } from './deployment-detail/fleet-deployment-detail.component';
import { FleetDeploymentsComponent } from './deployments/fleet-deployments.component';
import { FleetPublishComponent } from './publish/fleet-publish.component';
import { FleetReleaseReportsComponent } from './release-reports/fleet-release-reports.component';
import { FleetRolloutDetailComponent } from './rollout-detail/fleet-rollout-detail.component';
import { FleetRolloutsComponent } from './rollouts/fleet-rollouts.component';

/**
 * The fleet console's pages under `/xrm/fleet/**` (D-792 §7.1). The host
 * mounts these only when the build-time constant `ATTOME_FLEET_CONSOLE` is
 * true (the development build configuration), so a production bundle has no
 * fleet chunk at all. The whole console is one lazy chunk: it is a developer
 * tool, never on a customer's hot path. The four sidebar items the server's
 * `SidebarContributor` adds point at the first four paths.
 */
export const FLEET_ROUTES: Routes = [
  { path: '', pathMatch: 'full', redirectTo: 'deployments' },
  { path: 'deployments', component: FleetDeploymentsComponent },
  { path: 'deployments/:id', component: FleetDeploymentDetailComponent },
  { path: 'release-reports', component: FleetReleaseReportsComponent },
  { path: 'publish', component: FleetPublishComponent },
  { path: 'rollouts', component: FleetRolloutsComponent },
  { path: 'rollouts/:id', component: FleetRolloutDetailComponent },
];
