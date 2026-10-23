// M59 Phase 1 (Integration & Connectors) - external-system grid gets a
// "test connection" selection action (no bespoke list/form component - the
// generic metadata-driven pages already render every field
// integration_system declares). The unused mapping picker was removed
// (CLEANUP-REVIEW 4.9); a sync-configuration screen builds its own.
export { registerIntegrationEntityForms } from './registration/provide-integration-entity-forms';
// M13-T4: webhook subscriptions screen.
export { WebhookSubscriptionsComponent } from './webhooks/webhook-subscriptions.component';
