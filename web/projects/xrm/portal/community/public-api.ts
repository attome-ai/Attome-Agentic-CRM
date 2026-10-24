// G13-T2 — the portal community pages (`/community/:keyword`): categories,
// threads with their posts and accepted answer, and ideas with votes, over
// the portal's own record API (`/{keyword}/api/v1/records/forum_*`) and the
// community pack's entities (G13-T1). Its own entry point so only its route
// loads it.
export { ForumComponent, visibleItems } from './forum.component';
export { ForumService } from './forum.service';
export type { ForumCategory, ForumIdea, ForumPost, ForumThread, PortalRecord } from './forum.service';
