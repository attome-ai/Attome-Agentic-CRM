// @attome/xrm/portal/booking — the public booking page and its manage link
// (D20-T2/T3). Lazy-loaded by the host's `/book/...` routes.
export { BookPageComponent } from './booking-page.component';
export { BookManageComponent } from './booking-manage.component';
export { challengeToken, groupByDay, meetingTime, ownTimeZone, timeZones } from './booking';
export type { BookingPageView, ManagedBooking, SlotDay } from './booking';
