// L1-T9 — master data: the golden record panel (the record tab `golden` on a
// master entity's form, loaded on first open), its contributions, the held
// queue and the cross-reference search. Its own entry point so the record
// form's chunk does not carry it and the governance pages stay as they are
// (D-314). Services and wire types are in `@attome/xrm/core/admin/data`.
export { GoldenRecordPanelComponent } from './golden-record-panel.component';
export { ContributionsListComponent } from './contributions-list.component';
export { HELD_PAGE_SIZE, HeldQueueComponent } from './held-queue.component';
export { XrefSearchComponent } from './xref-search.component';
export { goldenRows, shown } from './golden-rows';
export type { GoldenRow } from './golden-rows';
