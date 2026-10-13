// @attome/xrm/core/entity/record-activity — U3/U6 (basic-units plan, D-601):
// the record timeline and record history panels, and their service.
//
// Their own entry point rather than `core/entity`'s barrel, for the same reason
// as `views` (U13): every bespoke entity form shares the `core/entity` widget
// chunk, which sits at the lazy-chunk budget (scripts/chunk-budget.mjs, D-314).
// `RecordTabPanelsComponent` loads this entry point with a dynamic `import()`
// the first time a Timeline or History tab is opened, so a form that never
// opens them never downloads them.
export { RecordTimelinePanelComponent, TIMELINE_PAGE_SIZE } from './timeline/record-timeline-panel.component';
export { RecordHistoryPanelComponent, historyValue }      from './history/record-history-panel.component';
export type { HistoryValue }                              from './history/record-history-panel.component';
export { RecordTimelineService, TIMELINE_KINDS }          from './timeline/record-timeline.service';
export type {
  RecordHistoryChange, RecordHistoryField, RecordHistoryPage, TimelineEntry, TimelineEntryKind,
  TimelinePage, TimelineRequest,
} from './timeline/record-timeline.service';
