// Y8-T12 — the metadata versions page (`/xrm/admin/metadata-versions`): the
// published versions, the current one, each version's node switch times and
// a rollback to the version before the current one.
//
// Its own secondary entry point, like `release-reports`, so routes that load
// the `@attome/xrm/core/admin` barrel do not download this page too (D-314).
export { MetadataVersionsComponent, MetadataVersionsService } from './metadata-versions.component';
export type { MetadataVersion, NodeSwitch, VersionSwitch } from './metadata-versions.component';
