/*
 * @attome/xrm/fleet — the developer's fleet console (D-792,
 * `document/general/FLEET-CONSOLE-DESIGN.md` §7.1): deployments, release
 * reports across customers, publish and rollouts.
 *
 * Only the host imports this entry point, lazily, and only when its build-time
 * constant `ATTOME_FLEET_CONSOLE` is true (`angular.json`, development
 * configuration). Nothing inside @attome/xrm imports it (D-314), so no other
 * chunk can pull it in. The server side answers only in a developer debug
 * build with the gate open, on loopback, for `system.admin`.
 */
export { FLEET_ROUTES } from './fleet.routes';
export { fleetAr, fleetEn } from './fleet.i18n';
export { FleetService, FLEET_API, FLEET_STEP_UP_OPERATION } from './data/fleet.service';
export type { ItemFilter } from './data/fleet.service';
export { fleetErrorText, fleetErrorCode, FLEET_ERROR_CODES } from './data/fleet-error-text';
export { FleetDeploymentsComponent } from './deployments/fleet-deployments.component';
export { FleetDeploymentDetailComponent } from './deployment-detail/fleet-deployment-detail.component';
export { FleetReleaseReportsComponent } from './release-reports/fleet-release-reports.component';
export { FleetPublishComponent } from './publish/fleet-publish.component';
export { FleetRolloutsComponent } from './rollouts/fleet-rollouts.component';
export { FleetRolloutDetailComponent } from './rollout-detail/fleet-rollout-detail.component';
export * from './data/fleet.types';
