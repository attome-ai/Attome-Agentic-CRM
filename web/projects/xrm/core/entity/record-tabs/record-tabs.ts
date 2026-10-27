import type { XrmFormTabDef } from '../base/xrm-form.base';

/**
 * The generic "about this record" tabs every entity form can carry beside its
 * own field tabs: attached documents, communications, notes, tags, consent
 * activities (tasks and phone calls, U2), the relationship explorer, and
 * (U3/U6, D-601) the record's timeline and field-level change history, and
 * (M9-T4) the approval requests about the record.
 * `EntityFormComponent` pioneered them;
 * `recordTabDefs` + `RecordTabPanelsComponent` let a hand-written
 * `EngineFormBase` subclass (the service ticket form, U14) include the same set,
 * or a subset of it, without copying the panel wiring.
 */
export type RecordTabId =
  'documents' | 'communications' | 'notes' | 'activities' | 'tags' | 'consent' | 'relationships'
  | 'timeline' | 'history' | 'approvals' | 'sharing' | 'golden' | 'fulfilment' | 'lines' | 'team' | 'splits';

/** Every record tab, in the order the generic form has always shown them. */
export const RECORD_TAB_IDS: readonly RecordTabId[] = [
  'documents', 'communications', 'notes', 'activities', 'tags', 'consent', 'relationships', 'timeline', 'history',
  'approvals', 'sharing', 'fulfilment', 'lines', 'team', 'splits',
];

const ICONS: Record<RecordTabId, string> = {
  documents:      'las la-folder-open',
  communications: 'las la-envelope',
  notes:          'las la-sticky-note',
  activities:     'las la-tasks',
  tags:           'las la-tags',
  consent:        'las la-check-circle',
  relationships:  'las la-project-diagram',
  timeline:       'las la-stream',
  history:        'las la-history',
  approvals:      'las la-user-check',
  sharing:        'las la-share-alt',
  golden:         'las la-fingerprint',
  fulfilment:     'las la-truck',
  lines:          'las la-list',
  team:           'las la-users',
  splits:         'las la-chart-pie',
};

const LABEL_KEYS: Record<RecordTabId, string> = {
  documents:      'xrmForm.tabs.documents',
  communications: 'xrmForm.tabs.communications',
  notes:          'xrmForm.tabs.notes',
  activities:     'xrmForm.tabs.activities',
  tags:           'xrmForm.tabs.tags',
  consent:        'xrmForm.tabs.consent',
  relationships:  'xrmForm.tabs.relationships',
  timeline:       'xrmForm.tabs.timeline',
  history:        'xrmForm.tabs.history',
  approvals:      'xrmForm.tabs.approvals',
  sharing:        'xrmForm.tabs.sharing',
  golden:         'xrmForm.tabs.golden',
  fulfilment:     'xrmForm.tabs.fulfilment',
  lines:          'xrmForm.tabs.lines',
  team:           'xrmForm.tabs.team',
  splits:         'xrmForm.tabs.splits',
};

/**
 * "Hide on my own entity": a document is not attached to itself, a note does
 * not take notes on itself, a tag category/application is not itself tagged,
 * and consent's own two entities do not record consent about themselves
 * (M24, D-428). Communications and Relationships have no such exception —
 * see `EntityFormComponent.defineTabs`' C-29 note.
 */
function hiddenOn(tab: RecordTabId, entityName: string): boolean {
  switch (tab) {
    case 'documents': return entityName === 'attome_document';
    case 'notes':     return entityName === 'note';
    case 'activities': return entityName === 'activity';
    case 'tags':      return entityName === 'tag_category' || entityName === 'tag_item';
    case 'consent':   return entityName === 'audit_consent' || entityName === 'audit_consent_purpose';
    // F6-T17: a sales order's fulfilment, line by line; only orders have it.
    case 'fulfilment': return entityName !== 'order';
    // D6-T10: an opportunity's lines.
    case 'lines':      return entityName !== 'opportunity';
    // D7-T7: an opportunity's team and credit splits.
    case 'team':       return entityName !== 'opportunity';
    case 'splits':     return entityName !== 'opportunity';
    default:          return false;
  }
}

/**
 * The record tabs `entityName`'s form should show, restricted to `include`
 * (every record tab by default) and always in `RECORD_TAB_IDS` order.
 * `translate` resolves the labels — pass `LangService.translate` so that,
 * called from `defineTabs()` inside the base class's `tabs` computed, the
 * labels follow a language switch.
 */
export function recordTabDefs(
  entityName: string,
  translate: (key: string) => string,
  include: readonly RecordTabId[] = RECORD_TAB_IDS,
): XrmFormTabDef[] {
  return RECORD_TAB_IDS
    .filter(id => include.includes(id) && !hiddenOn(id, entityName))
    .map(id => ({ id, label: translate(LABEL_KEYS[id]), icon: ICONS[id] }));
}

/**
 * L1-T9: a master entity's form gains the Golden record tab (values with
 * their sources, pins, contributions) after its record tabs. Not in
 * `RECORD_TAB_IDS`: it depends on the entity being master data, which only
 * the loaded schema says, so the form base adds it here. A form that shows
 * no record tabs gets none.
 */
export function withGoldenTab(
  tabs: XrmFormTabDef[],
  isMaster: boolean,
  translate: (key: string) => string,
): XrmFormTabDef[] {
  const hasRecordTabs = tabs.some(t => (RECORD_TAB_IDS as readonly string[]).includes(t.id));
  if (!isMaster || !hasRecordTabs || tabs.some(t => t.id === 'golden')) return tabs;
  return [...tabs, { id: 'golden', label: translate(LABEL_KEYS.golden), icon: ICONS.golden }];
}
