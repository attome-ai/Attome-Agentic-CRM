/*
 * @attome/xrm/core/entity/data — the entity data service, the entity route
 * registry and the entity URL helpers, apart from `@attome/xrm/core/entity`'s
 * components (AA14-T6). The signed-in shell needs only these; importing them
 * through the `core/entity` barrel brought every entity component (the list,
 * notes, field inputs, folders) into the shell's first download.
 * `@attome/xrm/core/entity` re-exports what it always exported from here.
 */
export * from './entity.service';
export * from './entity-route-registry.service';
export * from './entity-url.utils';
