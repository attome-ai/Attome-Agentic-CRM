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
