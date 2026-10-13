// Split out from `@attome/xrm/core/entity` (D-314 packaging: xrm barrel
// splitting) — EntityRouterComponent's route resolution and the generic list
// page are only needed by the wildcard entity route. Every per-entity form only
// needs the parent entry's widgets and EngineFormBase. The generic
// metadata-driven EntityFormComponent (and its EntityFormPageComponent
// wrapper) were removed: every entity has its own form in code, and an entity
// without one gets MissingFormPageComponent (SYSTEM-CHANGES.md Topic 14,
// FORMS-IN-CODE-PLAN.md §6 steps 2-3). EntityListComponent stays in
// the parent entry (not split here) because RelatedGridComponent is built
// directly on top of it, and RelatedGridComponent is a widget every form
// can use — splitting the list out would just re-create this same problem
// for every form with a related-records tab.
export { EntityListPageComponent }    from './pages/entity-list-page.component';
export { MissingFormPageComponent }   from './pages/missing-form-page.component';
export { DocumentsPageComponent }     from './pages/documents-page.component';
export { EntityRouterComponent }      from './entity-router.component';
