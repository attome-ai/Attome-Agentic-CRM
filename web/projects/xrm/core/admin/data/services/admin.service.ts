import { inject, Injectable } from '@angular/core';
import { map, Observable, tap } from 'rxjs';
import { ApiComponents, ApiService, LangService } from '@attome/base';
import { EntityMetadataChangeService } from './entity-metadata-change.service';

export const XRM_FIELD_TYPES = [
  'text', 'number', 'currency', 'date', 'bool', 'choice', 'lookup', 'file', 'icon', 'color',
  'formula', 'rich_text', 'image', 'date_time', 'time',
] as const;
export type XrmFieldType = typeof XRM_FIELD_TYPES[number];

// C-29 (M01 §7) — this used to be a hardcoded English `Record<XrmFieldType,
// string>`. Its one consumer (`entity-editor.component.ts::typeLabel`) now
// resolves `'fieldTypes.' + ft` through `LangService.translate()` instead
// (catalog keys in en.catalog.ts/ar.catalog.ts's `fieldTypes` namespace) —
// every field-type label is Arabic-first like everything else in the admin
// UI, not hardcoded English.

// P-api-contract (C-26): codegen-derived, not hand-written — closed two real
// drifts the previous hand-written interfaces had: `EntityMeta` never
// declared `is_append_only`, and `AttributeMeta` never declared
// `data_classification`/`is_filterable`/`is_sensitive`/`is_sortable`/
// `on_target_delete` even though `attribute.rs` has returned them for a
// while. `AttributeMeta.field_type` is narrowed back to `XrmFieldType`
// (the wire schema types it as a bare `string`, since utoipa has no
// visibility into the Rust-side `field_type.rs` enum's closed vocabulary) —
// the one field where codegen's type is *less* precise than the
// hand-maintained one, not more, so it is deliberately kept.
export type EntityMeta = ApiComponents['schemas']['EntityMeta'];

export type EntityDetail =
  Omit<ApiComponents['schemas']['EntityDetail'], 'attributes'> & { attributes: AttributeMeta[] };

export type AttributeMeta =
  Omit<ApiComponents['schemas']['AttributeMeta'], 'field_type'> & { field_type: XrmFieldType };

export type CreateEntityBody = ApiComponents['schemas']['CreateEntityBody'];
export type UpdateEntityBody = ApiComponents['schemas']['UpdateEntityBody'];

// `CreateAttributeBody`/`UpdateAttributeBody` stay hand-written: `attribute.rs`'s
// Rust request structs (`CreateAttributeBody`/`UpdateAttributeBody`) derive only
// `Deserialize`, not `ToSchema`, so neither reaches `openapi.json` — codegen has
// nothing to point at. That is a backend annotation gap (guidelines §12), not
// an Angular-side choice; out of scope for this Angular-only pass (C-26).
export interface CreateAttributeBody {
  logicalname:        string;
  name:               string;
  field_type:         XrmFieldType;
  is_required?:       boolean;
  max_length?:        number;
  lookup_entity_ref?: string;
  options?:           Record<string, unknown>;
}

export interface UpdateAttributeBody {
  name?:        string;
  field_type?:  XrmFieldType;
  is_required?: boolean;
  max_length?:  number;
  is_active?:   boolean;
  options?:     Record<string, unknown>;
}

// `child` is re-narrowed to non-optional: the wire type is genuinely optional
// (`sidebar.rs` sets `#[serde(skip_serializing_if = "Vec::is_empty")]`, so a
// leaf item's JSON omits the key entirely), but `shell.component.ts`'s
// `getSidebar()` call is the one ingestion point for this type and already
// guards it (`normalizeSidebar`'s `i.child ?? []`) before any other consumer
// ever sees a `SidebarItem` — every downstream read
// (`shell.component.ts`/`shell-sidebar.component.ts`) already assumes
// `child` is always a (possibly empty) array. Re-widening it back to
// optional here would just push that same `?? []` onto every one of those
// reads instead of the single place that already does it.
export type SidebarItem =
  Omit<ApiComponents['schemas']['SidebarItem'], 'child'> & { child: SidebarItem[] };

export type SidebarAdminItem = ApiComponents['schemas']['SidebarAdminItem'];

// Wire schema name is `SidebarPrivilegeItem` (`sidebar.rs`), not
// `SidebarPrivilege` — kept under this file's existing exported name so
// `sidebar-manager.component.ts` doesn't need to change.
export type SidebarPrivilege = ApiComponents['schemas']['SidebarPrivilegeItem'];

// `privilege_ids` is re-narrowed to non-optional for the same reason
// `SidebarItem.child` is above: the wire type has `#[serde(default)]`
// (`sidebar.rs`), so it is genuinely optional on the way IN, but every
// writer in this codebase (`sidebar-manager.component.ts`'s `blankDraft`/
// `fromItem`) already always supplies a concrete (possibly empty) array —
// re-widening it back to optional here would just push an `?? []` onto
// every one of those call sites instead of never needing one.
export type SidebarMutation =
  Omit<ApiComponents['schemas']['SidebarMutation'], 'privilege_ids'> & { privilege_ids: string[] };

/** D-404 / M83 Phase 1 — `calendar`, per-day working ranges as
 * minutes-from-midnight (`{"mon": [{"start_minute": 540, "end_minute":
 * 1020}], ...}`), matching `attome_calendar::TimeRange`'s wire shape exactly. */
export interface CalendarTimeRange {
  start_minute: number;
  end_minute:   number;
}

export interface CalendarAdminItem {
  id:            string;
  name:          string;
  description:   string | null;
  tz:            string;
  working_days:  string[];
  hours:         Record<string, CalendarTimeRange[]>;
  is_default:    boolean;
  is_active:     boolean;
  /** Solution 7 (D-785): the owning layer, typed from the generated `CalendarDetail`. */
  owner_layer?: ApiComponents['schemas']['CalendarDetail']['owner_layer'];
}

export interface CalendarMutation {
  name:          string;
  description?:  string | null;
  tz:            string;
  working_days:  string[];
  hours:         Record<string, CalendarTimeRange[]>;
  is_default:    boolean;
}

export interface CalendarHoliday {
  id:            string;
  calendar_id:   string;
  name:          string;
  /** `YYYY-MM-DD`. */
  holiday_date:  string;
}

export interface CalendarHolidayMutation {
  name:          string;
  holiday_date:  string;
}

/** D-592 — one date whose hours differ from the weekday's. */
export interface CalendarException {
  id:              string;
  calendar_id:     string;
  name:            string;
  /** `YYYY-MM-DD`. */
  exception_date:  string;
  /** Empty: closed that date. Otherwise these replace the weekday's hours. */
  ranges:          CalendarTimeRange[];
}

export interface CalendarExceptionMutation {
  name:            string;
  exception_date:  string;
  ranges:          CalendarTimeRange[];
}

/** M05 Phase 1 (D-426) — one `metadata_label` row scoped to an
 * entity (`crates/engine/attome-api/src/metadata_label_admin.rs`). */
export interface MetadataLabel {
  id:            string;
  object_kind:   'entity' | 'attribute' | 'choice_option';
  object_ref:    string;
  locale:        string;
  display_name:  string;
  description:   string | null;
  row_version:   number;
}

export interface MetadataLabelMutation {
  object_kind:             'entity' | 'attribute' | 'choice_option';
  /** Required for `attribute`/`choice_option`; ignored for `entity`. */
  attribute_logicalname?:  string;
  /** Required for `choice_option` only. */
  option_value?:           string;
  locale:                  string;
  display_name:            string;
  description?:            string | null;
}

/** M01 Core P3 gap (D-455) — one `relationship_info` row
 * (`crates/engine/attome-api/src/relationship_admin.rs`).
 *
 * NAME TRAP (found migrating this file for C-26): the generated schema keyed
 * `RelationshipDef` is `bundle/model.rs`'s bundle-export shape (no `id`, no
 * `row_version`, no `join_table`/`is_customized`) — a different Rust struct
 * that happens to share this admin type's old hand-written name. The actual
 * wire type for `/api/v1/admin/relationships*` is `RelationshipView`
 * (`relationship_admin.rs`); this alias keeps the pre-existing exported name
 * so `entity-editor.component.ts` doesn't need to change. `cascade` also
 * drops the old hand-written `'restrict' | 'orphan' | 'cascade_deactivate'`
 * union (already stale — the backend's canonical spelling is now hyphenated
 * `cascade-deactivate`, C-21) for the wire's plain `string`. */
export type RelationshipDef = ApiComponents['schemas']['RelationshipView'];

export type CreateRelationshipBody = ApiComponents['schemas']['CreateRelationshipBody'];
export type UpdateRelationshipBody = ApiComponents['schemas']['UpdateRelationshipBody'];

@Injectable({ providedIn: 'root' })
export class AdminService {
  private readonly api = inject(ApiService);
  /**
   * PERF-3 - every mutation below that changes what
   * `GET /api/v1/schema/{logicalname}` would return notifies through here, so
   * `EntityService`'s schema cache drops stale entries instead of serving them
   * until their TTL expires. Sidebar, autovalue and scaffold calls do not
   * notify: none of them change an entity's field set.
   */
  private readonly metadataChanged = inject(EntityMetadataChangeService);
  private readonly lang = inject(LangService);

  /** `tap` that fires the notifier only on a *successful* mutation. */
  private notifyOnSuccess<T>(): (source: Observable<T>) => Observable<T> {
    return source => source.pipe(tap(() => this.metadataChanged.notify()));
  }

  listEntities(): Observable<EntityMeta[]> {
    return this.api.getAllPages<EntityMeta>('/api/v1/admin/entities');
  }

  /** M05/D-426: `?locale=` threads `LangService.intlLocale()` (e.g. `"ar-SA"`)
   * so a translated sidebar label resolves the same requested -> deployment
   * default -> base-name chain the schema endpoint uses. */
  getSidebar(): Observable<SidebarItem[]> {
    return this.api.get<SidebarItem[]>('/api/v1/sidebar/get', { locale: this.lang.intlLocale() });
  }

  listSidebarAdmin(): Observable<SidebarAdminItem[]> {
    return this.api.getAllPages<SidebarAdminItem>('/api/v1/sidebar/admin');
  }

  listSidebarPrivileges(): Observable<SidebarPrivilege[]> {
    return this.api.getAllPages<SidebarPrivilege>('/api/v1/sidebar/admin/privileges');
  }

  createSidebarItem(body: SidebarMutation): Observable<SidebarAdminItem> {
    return this.api.post<SidebarAdminItem>('/api/v1/sidebar/admin', body);
  }

  updateSidebarItem(id: string, body: SidebarMutation): Observable<SidebarAdminItem> {
    return this.api.patch<SidebarAdminItem>(`/api/v1/sidebar/admin/${id}`, body);
  }

  // ── Calendars (D-404 / M83 Phase 1) ───────────────────────────────────────

  listCalendars(): Observable<CalendarAdminItem[]> {
    return this.api.getAllPages<CalendarAdminItem>('/api/v1/admin/calendars');
  }

  createCalendar(body: CalendarMutation): Observable<CalendarAdminItem> {
    return this.api.post<CalendarAdminItem>('/api/v1/admin/calendars', body);
  }

  updateCalendar(id: string, body: CalendarMutation): Observable<CalendarAdminItem> {
    return this.api.patch<CalendarAdminItem>(`/api/v1/admin/calendars/${id}`, body);
  }

  deleteCalendar(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/calendars/${id}`);
  }

  listHolidays(calendarId: string): Observable<CalendarHoliday[]> {
    return this.api.get<CalendarHoliday[]>(`/api/v1/admin/calendars/${calendarId}/holidays`);
  }

  createHoliday(calendarId: string, body: CalendarHolidayMutation): Observable<CalendarHoliday> {
    return this.api.post<CalendarHoliday>(`/api/v1/admin/calendars/${calendarId}/holidays`, body);
  }

  deleteHoliday(calendarId: string, holidayId: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/calendars/${calendarId}/holidays/${holidayId}`);
  }

  listExceptions(calendarId: string): Observable<CalendarException[]> {
    return this.api.get<CalendarException[]>(`/api/v1/admin/calendars/${calendarId}/exceptions`);
  }

  createException(calendarId: string, body: CalendarExceptionMutation): Observable<CalendarException> {
    return this.api.post<CalendarException>(`/api/v1/admin/calendars/${calendarId}/exceptions`, body);
  }

  deleteException(calendarId: string, exceptionId: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/calendars/${calendarId}/exceptions/${exceptionId}`);
  }

  // ── Metadata labels (M05 Phase 1, D-426) ─────────────────────────────────

  listLabels(entityId: string): Observable<MetadataLabel[]> {
    return this.api.get<MetadataLabel[]>(`/api/v1/admin/entities/${entityId}/labels`);
  }

  createLabel(entityId: string, body: MetadataLabelMutation): Observable<MetadataLabel> {
    return this.api
      .post<MetadataLabel>(`/api/v1/admin/entities/${entityId}/labels`, body)
      .pipe(this.notifyOnSuccess());
  }

  updateLabel(
    entityId: string,
    labelId: string,
    body: MetadataLabelMutation,
  ): Observable<MetadataLabel> {
    return this.api
      .patch<MetadataLabel>(`/api/v1/admin/entities/${entityId}/labels/${labelId}`, body)
      .pipe(this.notifyOnSuccess());
  }

  deleteLabel(entityId: string, labelId: string): Observable<void> {
    return this.api
      .delete(`/api/v1/admin/entities/${entityId}/labels/${labelId}`)
      .pipe(this.notifyOnSuccess());
  }

  // ── Relationships (M01 Core P3 gap, D-455) ───────────────────────────────
  //
  // Top-level resource, not nested under an entity id — a relationship names
  // both its sides itself. `entity` narrows to relationships touching one
  // entity on either side, same `?entity=` convention `listRelationships`
  // (the Rust handler) uses. One-based like every offset list (D-793), which
  // is `getAllPages`' default.

  listRelationships(entity?: string): Observable<RelationshipDef[]> {
    return this.api.getAllPages<RelationshipDef>(
      '/api/v1/admin/relationships', entity ? { entity } : {},
    );
  }

  createRelationship(body: CreateRelationshipBody): Observable<RelationshipDef> {
    return this.api
      .post<RelationshipDef>('/api/v1/admin/relationships', body)
      .pipe(this.notifyOnSuccess());
  }

  updateRelationship(id: string, body: UpdateRelationshipBody): Observable<RelationshipDef> {
    return this.api
      .patch<RelationshipDef>(`/api/v1/admin/relationships/${id}`, body)
      .pipe(this.notifyOnSuccess());
  }

  /** Soft-retires the relationship DEFINITION only — the physical join
   * table and its link rows are never dropped (see the Rust handler's own
   * doc comment). */
  deleteRelationship(id: string): Observable<void> {
    return this.api
      .delete(`/api/v1/admin/relationships/${id}`)
      .pipe(this.notifyOnSuccess());
  }

  getEntity(id: string): Observable<EntityDetail> {
    return this.api.get<EntityDetail>(`/api/v1/admin/entities/${id}`);
  }

  createEntity(body: CreateEntityBody): Observable<EntityMeta> {
    return this.api
      .post<EntityMeta>('/api/v1/admin/entities', body)
      .pipe(this.notifyOnSuccess());
  }

  updateEntity(id: string, body: UpdateEntityBody): Observable<EntityMeta> {
    return this.api
      .patch<EntityMeta>(`/api/v1/admin/entities/${id}`, body)
      .pipe(this.notifyOnSuccess());
  }

  deleteEntity(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/entities/${id}`).pipe(this.notifyOnSuccess());
  }

  createAttribute(entityId: string, body: CreateAttributeBody): Observable<AttributeMeta> {
    return this.api
      .post<AttributeMeta>(`/api/v1/admin/entities/${entityId}/fields`, body)
      .pipe(this.notifyOnSuccess());
  }

  updateAttribute(entityId: string, attrId: string, body: UpdateAttributeBody): Observable<AttributeMeta> {
    return this.api
      .patch<AttributeMeta>(`/api/v1/admin/entities/${entityId}/fields/${attrId}`, body)
      .pipe(this.notifyOnSuccess());
  }

  deleteAttribute(entityId: string, attrId: string): Observable<void> {
    return this.api
      .delete(`/api/v1/admin/entities/${entityId}/fields/${attrId}`)
      .pipe(this.notifyOnSuccess());
  }

  // ── Dev-only scaffolding (never present against a deployed backend) ──────

  devToolsAvailable(): Observable<DevToolsInfo> {
    return this.api.get<DevToolsInfo>('/api/v1/admin/dev-tools/available');
  }

  /**
   * Writes a three-file (.ts/.html/.css) form or list component override for
   * `entityId` into `targetDir`, and registers it in provide-xrm-forms.ts when
   * that directory sits under projects/xrm/forms/. Dev-only — 404s against any
   * backend not running with APP_ENV=debug + ATTOME_DEV_SCAFFOLD=1.
   */
  scaffoldComponent(
    entityId: string,
    kind: ScaffoldKind,
    targetDir: string,
  ): Observable<ScaffoldResult> {
    return this.api.post<ScaffoldResult>(
      `/api/v1/admin/entities/${entityId}/scaffold-ui`,
      { kind, target_dir: targetDir },
    );
  }

  // ── Auto Value rules ─────────────────────────────────────────────────────
  //
  // `autovalue` is an ordinary metadata-defined entity (see
  // attome-metadata's autovalue.rs), so these go through the generic record
  // endpoints rather than a bespoke admin route: the list is its seeded
  // default query filtered by target entity, and writes are plain entity CRUD.

  listAutoValues(entityLogicalname: string): Observable<AutoValueRule[]> {
    return this.api.post<QueryExecEnvelope>('/api/v1/query/execute', {
      entity:        AUTOVALUE_ENTITY,
      page:          1,
      page_size:     200,
      order_by:      'attribute_logicalname',
      order_dir:     'asc',
      // `entity_logicalname` is the one attribute autovalue.rs registers as
      // filterable, which is exactly this lookup.
      filters:       [{ field: 'entity_logicalname', op: 'eq', value: entityLogicalname }],
      include_total: false,
    }).pipe(map(res => res.data.records.map(toAutoValueRule)));
  }

  createAutoValue(body: AutoValueMutation): Observable<Record<string, unknown>> {
    return this.api.post<Record<string, unknown>>(`/api/v1/${AUTOVALUE_ENTITY}`, body);
  }

  updateAutoValue(
    id: string,
    body: AutoValueMutation,
    rowVersion: number,
  ): Observable<Record<string, unknown>> {
    return this.api.patch<Record<string, unknown>>(
      `/api/v1/${AUTOVALUE_ENTITY}/${id}`,
      body,
      rowVersion,
    );
  }

  deleteAutoValue(id: string): Observable<void> {
    return this.api.delete(`/api/v1/${AUTOVALUE_ENTITY}/${id}`);
  }

}

// ── Dev scaffolding types ────────────────────────────────────────────────────

export type ScaffoldKind = 'form' | 'list';

export interface DevToolsInfo {
  available: boolean;
  /** Absolute path of the backend's angular/ checkout — the containment root. */
  angular_root: string;
  /** Conventional override home; the only subtree that is auto-registered. */
  suggested_dir: string;
}

export type ScaffoldResult = ApiComponents['schemas']['ScaffoldResult'];

// ── Auto Value types ─────────────────────────────────────────────────────────

export const AUTOVALUE_ENTITY = 'autovalue';

/** Mirrors ResetScope in attome-metadata's autovalue.rs. */
export const AUTOVALUE_RESET_SCOPES = ['never', 'yearly', 'monthly', 'daily'] as const;
export type AutoValueResetScope = typeof AUTOVALUE_RESET_SCOPES[number];

export interface AutoValueRule {
  id:                    string;
  name:                  string;
  entity_logicalname:    string;
  attribute_logicalname: string;
  format:                string;
  initial_value:         number;
  next_value:            number;
  reset_scope:           AutoValueResetScope;
  scope_key:             string;
  row_version:           number;
}

export interface AutoValueMutation {
  name:                  string;
  entity_logicalname:    string;
  attribute_logicalname: string;
  format:                string;
  initial_value:         number;
  reset_scope:           AutoValueResetScope;
}

/** Only the envelope fields listAutoValues actually reads. */
interface QueryExecEnvelope {
  data: { records: Record<string, unknown>[] };
}

function toAutoValueRule(r: Record<string, unknown>): AutoValueRule {
  const scope = String(r['reset_scope'] ?? 'never') as AutoValueResetScope;
  return {
    id:                    String(r['id'] ?? ''),
    name:                  String(r['name'] ?? ''),
    entity_logicalname:    String(r['entity_logicalname'] ?? ''),
    attribute_logicalname: String(r['attribute_logicalname'] ?? ''),
    // A rule saved without a format still numbers records — autovalue.rs
    // falls back to '{SEQ}' server-side, so show that rather than a blank.
    format:                String(r['format'] ?? '') || '{SEQ}',
    initial_value:         Number(r['initial_value'] ?? 1),
    next_value:            Number(r['next_value'] ?? 1),
    reset_scope:           AUTOVALUE_RESET_SCOPES.includes(scope) ? scope : 'never',
    scope_key:             String(r['scope_key'] ?? ''),
    row_version:           Number(r['row_version'] ?? 0),
  };
}
