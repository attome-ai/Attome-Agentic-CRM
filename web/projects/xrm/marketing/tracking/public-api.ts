// @attome/xrm/marketing/tracking — the website tracking screen (E14-T12):
// embed code, visits report and live visitors, its own entry point so only
// its route loads it.
export { TrackingPageComponent, barShares, embedSnippet } from './tracking-page.component';
export { TrackingService, toSite } from './tracking.service';
export type { LiveVisitor, ReportRow, TrackedSite, TrackingReport } from './tracking.service';
