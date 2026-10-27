// @attome/xrm/core/admin/app-designer — A21-T3: an app's navigation on the
// shared canvas, its settings, simple mode and dependency map.
export { AppDesignerComponent, PICKABLE_KINDS } from './app-designer.component';
export type { Dependency, SourceObject } from './app-designer.component';
export { AppListComponent } from './app-list.component';
export {
  ITEM_KINDS, cleanSettings, groupNode, groupsOf, itemNode, itemPaths, navProblems, navigationOf, saveCommands, toCanvas, uuidv7,
} from './app-design.model';
export type { AppDoc, AppNode, AppSettings, ItemKind, NavGroup, NavItem, Navigation, SaveCommand } from './app-design.model';
