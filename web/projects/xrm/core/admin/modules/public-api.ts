// Module Management and Feature Flags (D-778, M95/D-430), moved here from the
// retired `@attome/xrm/license` entry point once licensing went away.
//
// Its own secondary entry point rather than more components on
// `@attome/xrm/core/admin`'s barrel: every route that loads that barrel
// would otherwise download these two pages too (D-314). The services and
// wire types live in `@attome/xrm/core/admin/data`, per the `/data` shape.
export { ModuleManagementComponent }  from './module-management/module-management.component';
export { FeatureFlagsAdminComponent } from './feature-flags/feature-flags-admin.component';
export { UsageComponent } from './usage/usage.component';
export { LatencyComponent } from './latency/latency.component';
export { BrandingComponent } from './branding/branding.component';
