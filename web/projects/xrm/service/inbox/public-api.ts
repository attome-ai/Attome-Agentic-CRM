// @attome/xrm/service/inbox — the shared inbox (C8-T1), its own entry point
// so only its route loads it.
export { InboxComponent, TICKET_STATUSES, filterRows, toRow } from './inbox.component';
export type { InboxConversation, InboxFilter, InboxMailbox, InboxRow } from './inbox.component';
