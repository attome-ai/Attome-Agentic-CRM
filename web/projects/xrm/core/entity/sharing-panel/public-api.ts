// @attome/xrm/core/entity/sharing-panel — Q14-T6: a record's Sharing tab
// (owner, unit, shares, and why a person can see the record).
//
// Its own entry point, like `record-activity`: every entity form shares the
// `core/entity` widget chunk, which sits at the lazy-chunk budget (D-314).
// `RecordTabPanelsComponent` loads it with a dynamic `import()` the first time
// a Sharing tab is opened.
export { SharingPanelComponent } from './sharing-panel.component';
export { SharingPanelService, EXPLAIN_ACTIONS } from './sharing-panel.service';
export type {
  AccessExplanation, AccessSource, ExplainAction, PrincipalKind, PrincipalOption, RecordShare,
} from './sharing-panel.service';
