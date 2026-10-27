import { EntityRouteRegistry } from '@attome/xrm/core/entity';
import { DocumentFormComponent } from './document/form/document-form/document-form.component';
import { NoteFormComponent } from './note/form/note-form/note-form.component';
import { CoreApikeyFormComponent } from './forms/core-apikey-form/core-apikey-form.component';
import { CoreAuthenticationTypeFormComponent } from './forms/core-authentication-type-form/core-authentication-type-form.component';
import { CoreAutovalueFormComponent } from './forms/core-autovalue-form/core-autovalue-form.component';
import { DocgenTemplateFormComponent } from './forms/docgen-template-form/docgen-template-form.component';
import { CommunicationFormComponent } from './forms/communication-form/communication-form.component';
import { CommunicationEventFormComponent } from './forms/communication-event-form/communication-event-form.component';
import { FollowFormComponent } from './forms/follow-form/follow-form.component';
import { FeedPostFormComponent } from './forms/feed-post-form/feed-post-form.component';
import { NoteReplyFormComponent } from './forms/note-reply-form/note-reply-form.component';
import { GlossaryTermFormComponent } from './forms/glossary-term-form/glossary-term-form.component';
import { CoreLicenseFormComponent } from './forms/core-license-form/core-license-form.component';
import { ProfilerFindingFormComponent } from './forms/profiler-finding-form/profiler-finding-form.component';
import { RecordRelationshipFormComponent } from './forms/record-relationship-form/record-relationship-form.component';
import { ResourceSkillFormComponent } from './forms/resource-skill-form/resource-skill-form.component';
import { ResourceAvailabilityFormComponent } from './forms/resource-availability-form/resource-availability-form.component';
import { TagCategoryFormComponent } from './forms/tag-category-form/tag-category-form.component';
import { TagItemFormComponent } from './forms/tag-item-form/tag-item-form.component';
import { ReminderFormComponent } from './forms/reminder-form/reminder-form.component';
import { ActivityFormComponent } from './forms/activity-form/activity-form.component';
import { ScanActionFormComponent } from './forms/scan-action-form/scan-action-form.component';
import { TaskChecklistItemFormComponent } from './forms/task-checklist-item-form/task-checklist-item-form.component';
import { QueueFormComponent } from './forms/queue-form/queue-form.component';
import { QueueItemFormComponent } from './forms/queue-item-form/queue-item-form.component';
import { QueueItemSkillFormComponent } from './forms/queue-item-skill-form/queue-item-skill-form.component';
import { AgentChannelCapacityFormComponent } from './forms/agent-channel-capacity-form/agent-channel-capacity-form.component';
import { SocialProfileFormComponent } from './forms/social-profile-form/social-profile-form.component';

// 'attome_document'/'note' -> their own dedicated forms. Split into this
// separate, lighter entry (rather than living directly in `core/entity`
// alongside EntityRouteRegistry itself) for the same bundle-splitting reason
// every other module's registration lives in its own `*/registration` entry
// — see core/security/registration/provide-security-entity-forms.ts's doc
// comment. A static import of this file must not drag in `core/entity`'s
// full surface (EntityFormComponent, EntityListComponent, notes-panel,
// document-folder-browser, …), which is genuinely large.
//
// Called from `EntityRouteRegistry.ensureLoaded`'s lazy `import()`, not
// eagerly — see that class's doc comment for why.
export function registerCoreEntityForms(registry: EntityRouteRegistry): void {
  registry.register('attome_document', { formComponent: DocumentFormComponent });
  registry.register('note', { formComponent: NoteFormComponent });
  registry.register('api_key', { formComponent: CoreApikeyFormComponent });
  registry.register('authentication_type', { formComponent: CoreAuthenticationTypeFormComponent });
  registry.register('autovalue', { formComponent: CoreAutovalueFormComponent });
  registry.register('docgen_template', { formComponent: DocgenTemplateFormComponent });
  registry.register('communication', { formComponent: CommunicationFormComponent });
  registry.register('communication_event', { formComponent: CommunicationEventFormComponent });
  registry.register('follow', { formComponent: FollowFormComponent });
  registry.register('feed_post', { formComponent: FeedPostFormComponent });
  registry.register('note_reply', { formComponent: NoteReplyFormComponent });
  registry.register('glossary_term', { formComponent: GlossaryTermFormComponent });
  registry.register('license', { formComponent: CoreLicenseFormComponent });
  registry.register('profiler_finding', { formComponent: ProfilerFindingFormComponent });
  registry.register('record_relationship', { formComponent: RecordRelationshipFormComponent });
  registry.register('resource_skill', { formComponent: ResourceSkillFormComponent });
  registry.register('resource_availability', { formComponent: ResourceAvailabilityFormComponent });
  registry.register('tag_category', { formComponent: TagCategoryFormComponent });
  registry.register('tag_item', { formComponent: TagItemFormComponent });
  registry.register('reminder', { formComponent: ReminderFormComponent });
  registry.register('activity', { formComponent: ActivityFormComponent });
  registry.register('scan_action', { formComponent: ScanActionFormComponent });
  registry.register('task_checklist_item', { formComponent: TaskChecklistItemFormComponent });
  // V7-T1, G4-T1: the generic queue, its items and their required skills.
  registry.register('queue', { formComponent: QueueFormComponent });
  registry.register('queue_item', { formComponent: QueueItemFormComponent });
  registry.register('queue_item_skill', { formComponent: QueueItemSkillFormComponent });
  // J10-T1: how many items an agent handles at once per channel.
  registry.register('agent_channel_capacity', { formComponent: AgentChannelCapacityFormComponent });
  // J8-T2: a person on a social channel.
  registry.register('social_profile', { formComponent: SocialProfileFormComponent });
}
