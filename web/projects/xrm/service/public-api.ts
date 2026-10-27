export { ServiceAdminService } from './services/service-admin.service';
export type { OfferingSummary, CreateWorkRequestFromOfferingRequest, CreateWorkRequestFromOfferingResponse } from './services/service-admin.service';
export { NewRequestPickerComponent } from './new-request/new-request-picker/new-request-picker.component';
// G2-T4: the triage board.
export { TriageBoardComponent } from './triage/triage-board.component';
// G3-T3: the service catalog with cart and my orders.
export { CatalogComponent } from './catalog/catalog.component';
export { itemCancellable } from './services/service-admin.service';
export type { CatalogOffering, CartLine, OrderView, OrderItemView, OrderPlaced, OrderRecipient } from './services/service-admin.service';
export { TRIAGE_STATUSES, triageColumns } from './services/service-admin.service';
export type { TriageItem, ConversionMapOption, KnowledgeSuggestion } from './services/service-admin.service';
export { registerServiceEntityForms } from './provide-service-entity-forms';
// U14 — ticket SLA: the service over `sla.rs`/`clock.rs`, the status badge
// (reusable in a list cell) and the pure status derivation behind it.
export { SlaService, SLA_PAUSE_REASONS } from './sla/sla.service';
export type {
  ApplySlaPolicyResponse, SlaClockView, SlaRecalculation, SlaPauseReason, SlaUnresolvedReason,
} from './sla/sla.service';
export { slaBadgeState, relativeTime } from './sla/sla-status';
export type { SlaBadgeKind, SlaBadgeState } from './sla/sla-status';
export { SlaBadgeComponent } from './sla/sla-badge/sla-badge.component';
export { SlaBadgeCellComponent } from './sla/sla-badge-cell/sla-badge-cell.component';
export { TicketSlaActionsComponent } from './sla/ticket-sla-actions/ticket-sla-actions.component';
// AI7-T6: ticket hand-offs — the card on the ticket and my hand-offs ('service/handoffs').
export { ServiceHandoffCardComponent } from './handoff/service-handoff-card.component';
export { ServiceHandoffsListComponent } from './handoff/service-handoffs-list.component';
export { ServiceHandoffService, canHandBack, partyIcon } from './handoff/service-handoff.service';
export type { ServiceHandoff } from './handoff/service-handoff.service';
// G4-T3: my queues ('service/queues') over the V7 queue items.
export { MyQueuesComponent } from './queues/my-queues.component';
export { MyQueuesService, STARTER_SETS, groupByQueue, missingStarters } from './queues/my-queues.service';
export type { QueueRef, QueueItemRow, QueueItemState, QueueGroup, StarterSetKey, StarterQueue, BulkOutcome } from './queues/my-queues.service';
