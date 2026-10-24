// @attome/xrm/core/entity/views — D-429/M64, the three non-list view kinds
// (`kind = list` stays `EntityListComponent` in `@attome/xrm/core/entity`).
// Each is self-contained: it resolves its own kind-matching view via
// `ViewAdminService`/`QueryService` and renders over the SAME already-
// privilege-/record-security-gated feed a list view uses
// (`POST /api/v1/query/execute`) — no separate events endpoint.
//
// Their own entry point (U13) rather than `core/entity`'s barrel: every bespoke
// entity form shares the `core/entity` widget chunk, and the list page is the
// only screen that renders these, so keeping them here keeps that shared chunk
// under the lazy-chunk budget (scripts/chunk-budget.mjs, D-314).
export { KanbanBoardComponent }  from './kanban/kanban-board.component';
export { CalendarViewComponent } from './calendar/calendar-view.component';
export { TimelineViewComponent } from './timeline/timeline-view.component';
// I3-T1 — the timeline's resource mode: the dispatch board.
export { DAY_FROM_HOUR, DAY_TO_HOUR, ResourceBoardComponent, axisHours, barGeometry } from './timeline/resource-board.component';
export type { BoardGhost, BoardJob, BoardTechnician } from './timeline/resource-board.component';
// V4-T1 — the project booking board, the timeline's resource mode for projects.
export {
  BOOKING_WEEKS, BookingBoardComponent, DEFAULT_ALLOCATION_PERCENT, addDays, spanGeometry, weekStart,
} from './timeline/booking-board.component';
export type { Booking, BookingPerson, Leave } from './timeline/booking-board.component';
