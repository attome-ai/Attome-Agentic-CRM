// Basic Units U19 (data quality M14, data catalog M18, change feed M89) and
// U8 (state models M07) — the governance admin screens.
//
// Its own secondary entry point rather than more components on
// `@attome/xrm/core/admin`'s barrel: every route that loads that barrel
// would otherwise download these four pages too (D-314). The services and
// wire types live in `@attome/xrm/core/admin/data`, per the `/data` shape.
export { GovernanceNavComponent }       from './nav/governance-nav.component';
export { DataQualityComponent }         from './data-quality/data-quality.component';
export { DataCatalogComponent }         from './data-catalog/data-catalog.component';
export { ChangeFeedComponent }          from './change-feed/change-feed.component';
export { StateModelsManagerComponent }  from './state-models/state-models-manager.component';
export { StateDiagramComponent }        from './state-diagram/state-diagram.component';
// L5-T7 — the lineage canvas, its cleanup list, and the impact panel the
// field-change preview shows.
export { LineageComponent }             from './lineage/lineage.component';
export { LineageGraphComponent }        from './lineage/lineage-graph.component';
export { CleanupListComponent }         from './lineage/cleanup-list.component';
export { ImpactPanelComponent }         from './lineage/impact-panel.component';
export { NODE_H, NODE_W, layoutLineage, walkTarget } from './lineage/lineage-layout';
export type { LineageLayout, PlacedEdge, PlacedNode } from './lineage/lineage-layout';
// L1-T9 — the steward's master-data page (its components are the
// `governance/master-data` entry point, which the record form loads too).
export { MasterDataPageComponent }      from './master-data-page/master-data-page.component';
