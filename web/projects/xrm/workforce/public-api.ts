// G17-T13: the workforce screens — schedules as a grid with coverage, the
// publish bar, swaps, intraday proposals and live adherence.
export { WorkforceApiService, coverageDays } from './workforce-api.service';
export type {
  AssignmentView, DayCoverage, LiveRow, OfferRow, OfferState, PickOption, Published, ScheduleDetail, ScheduleSummary,
  SwapResult, SwapRow,
} from './workforce-api.service';
export {
  ScheduleGridComponent, dayTotals, gridRows, scheduleDays,
} from './schedule-grid/schedule-grid.component';
export type { DayTotal, GridBar, GridRow } from './schedule-grid/schedule-grid.component';
export { WorkforcePageComponent, writeErrorKey } from './workforce-page.component';
export type { WorkforceTab } from './workforce-page.component';
// G17-T14: a person's own schedule, give-aways and offers, for a phone.
export { MY_SCHEDULE_DAYS, MyScheduleComponent, addDays, dayKey, scheduleByDay } from './me/my-schedule.component';
export type { ScheduleDay } from './me/my-schedule.component';
