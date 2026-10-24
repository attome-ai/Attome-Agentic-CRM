// T2-T2 — the page runtime: renders a published page (the page kind) with
// its component palette, bindings, events and visibility rules. Its own
// entry point so only the routes that show pages load it.
export { PageRuntimeComponent } from './page-runtime.component';
export { PageNodeComponent } from './page-node.component';
export { PageContext } from './page-context';
export { PAGE_ROWS, PageDataService } from './page-data.service';
export type { PageRows } from './page-data.service';
export { deviceOf, fillTarget, isVisible, seriesOf, textProp } from './page-model';
export type {
  Device, PageBinding, PageDoc, PageEvent, PageNode, PageNodeType, PageVisibility, VisibilityContext,
} from './page-model';
