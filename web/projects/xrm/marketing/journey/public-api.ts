// @attome/xrm/marketing/journey — what the workflow editor adds for a
// journey (E8-T13): live counts on the canvas, a person's path replayed and
// the version-move choice on publish. Loaded only for a journey.
export { JourneyCountsOverlayComponent, COUNTS_POLL_MS, countsFor } from './journey-counts-overlay.component';
export type { OverlayNode } from './journey-counts-overlay.component';
export { PersonPathComponent } from './person-path.component';
export { VersionMoveDialogComponent } from './version-move-dialog.component';
export { JourneyService } from './journey.service';
export type {
  JourneyCounts, JourneyNodeCount, JourneyPublishResult, NodeWaiting, PersonRun, VersionMode,
} from './journey.service';
