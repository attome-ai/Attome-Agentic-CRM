import { ChangeDetectionStrategy, Component, inject, input, OnInit, signal } from '@angular/core';
import { catchError, of } from 'rxjs';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  AdminService, AttributeMeta, EntityDetail, EntityMeta,
  AutoValueResetScope, AutoValueRule,
  MetadataLabel, MetadataLabelMutation,
  RelationshipDef, CreateRelationshipBody,
  XrmFieldType,
  DataProfileService, fillRates,
} from '@attome/xrm/core/admin/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';
import { FormulaEditorComponent } from '@attome/xrm/core/admin/formula-editor';
import {
  FieldChangeDialogComponent, type FieldChangeMode,
} from '../../field-changes/field-change-dialog/field-change-dialog.component';
import { RecoveryArchiveComponent } from '../../field-changes/recovery-archive/recovery-archive.component';
import { BinSettingsComponent } from '../../bin-settings/bin-settings.component';
import { FillRateBadgeComponent } from './fill-rate-badge.component';

type RelationshipCascade = 'restrict' | 'orphan' | 'cascade_deactivate';
const RELATIONSHIP_CASCADE_LABELS: Record<RelationshipCascade, string> = {
  restrict:            'Restrict (reserved — not yet enforced)',
  orphan:              'Orphan (link stays; hidden once either side is inactive)',
  cascade_deactivate:  'Cascade deactivate (reserved — not yet enforced)',
};

// C-26: `RelationshipDef.cascade` is now the generated `RelationshipView`
// schema's plain `string` (accurate — the wire has no enum here, just a
// column CHECK constraint), not the local `RelationshipCascade` literal
// union above. `relationship_admin.rs::cascade_from_wire` accepts BOTH the
// hyphenated canonical spelling (`cascade-deactivate`, C-21) and the older
// underscore one this map was written against — falling back to the raw
// value for anything else keeps a row this map doesn't recognize (a future
// spelling, or a value from a caller other than this form) visible instead
// of throwing.
function cascadeLabelFor(c: string): string {
  return RELATIONSHIP_CASCADE_LABELS[c as RelationshipCascade]
    ?? RELATIONSHIP_CASCADE_LABELS[c.replace(/-/g, '_') as RelationshipCascade]
    ?? c;
}

const RESET_SCOPE_LABELS: Record<AutoValueResetScope, string> = {
  never:   'Never',
  yearly:  'Every year',
  monthly: 'Every month',
  daily:   'Every day',
};

// ── Format preview ────────────────────────────────────────────────────────────
//
// A read-only mirror of `render_format` in attome-metadata's autovalue.rs, so an
// admin can see what `AVG-{DDDD}-{YY-MM-DD}` actually produces while typing it.
// Presentation only — the server allocates and renders the real value; if the
// two ever disagree the server is right. Kept faithful to the three rules that
// make the language readable: a token of only D/# is the sequence (width = its
// length), `{{`/`}}` are literal braces, and an unterminated `{` is emitted
// verbatim rather than swallowing the rest of the string.

const DATE_UNITS: readonly [string, (d: Date) => string][] = [
  ['YYYY', d => String(d.getUTCFullYear())],
  ['YY',   d => String(d.getUTCFullYear() % 100).padStart(2, '0')],
  ['MM',   d => String(d.getUTCMonth() + 1).padStart(2, '0')],
  ['DD',   d => String(d.getUTCDate()).padStart(2, '0')],
  ['HH',   d => String(d.getUTCHours()).padStart(2, '0')],
  ['mm',   d => String(d.getUTCMinutes()).padStart(2, '0')],
  ['ss',   d => String(d.getUTCSeconds()).padStart(2, '0')],
];

function renderDatePattern(pattern: string, now: Date): string {
  let out = '';
  let i = 0;
  outer: while (i < pattern.length) {
    for (const [unit, render] of DATE_UNITS) {
      // Case-sensitive on purpose: MM is month, mm is minute.
      if (pattern.startsWith(unit, i)) { out += render(now); i += unit.length; continue outer; }
    }
    out += pattern[i];
    i += 1;
  }
  return out;
}

function renderToken(token: string, seq: number, now: Date): string {
  if (token.length > 0 && /^[D#]+$/.test(token)) {
    return String(seq).padStart(token.length, '0');
  }
  if (token === 'SEQ') return String(seq);
  if (token.startsWith('SEQ:')) {
    const width = Number(token.slice(4));
    return Number.isInteger(width) && width > 0 ? String(seq).padStart(width, '0') : String(seq);
  }
  return renderDatePattern(token, now);
}

export function renderFormat(format: string, seq: number, now: Date): string {
  let out = '';
  let i = 0;
  while (i < format.length) {
    if (format.startsWith('{{', i)) { out += '{'; i += 2; continue; }
    if (format.startsWith('}}', i)) { out += '}'; i += 2; continue; }
    if (format[i] === '{') {
      const end = format.indexOf('}', i + 1);
      if (end === -1) { out += format.slice(i); break; }
      out += renderToken(format.slice(i + 1, end), seq, now);
      i = end + 1;
      continue;
    }
    out += format[i];
    i += 1;
  }
  return out;
}

// ── System fields ────────────────────────────────────────────────────────────
//
// Every provisioned entity table carries these columns in addition to its
// metadata-defined attributes (D-005 table conventions) — they are never rows
// in attribute_info, so AdminService's EntityDetail never returns
// them. Listed here as a static, read-only reference so an admin building a
// lookup or an Auto Value rule knows they exist, without implying they can be
// edited or deleted like an ordinary field. `organization_ref`/`row_version`/
// `owner_type` are omitted — internal bookkeeping with no business meaning to
// surface here.

interface SystemField {
  name:        string;
  type_label:  string;
  badge_class: string;
  description: string;
}

const SYSTEM_FIELDS: SystemField[] = [
  { name: 'ID',          type_label: 'System', badge_class: 'ee-type-system', description: 'Unique identifier, assigned automatically when the item is created.' },
  { name: 'Created On',  type_label: 'Date',   badge_class: 'ee-type-date',   description: 'When the item was first created.' },
  { name: 'Created By',  type_label: 'Lookup', badge_class: 'ee-type-lookup', description: 'Links to: User' },
  { name: 'Modified On', type_label: 'Date',   badge_class: 'ee-type-date',   description: 'When the item was last changed.' },
  { name: 'Modified By', type_label: 'Lookup', badge_class: 'ee-type-lookup', description: 'Links to: User' },
  { name: 'Owner',       type_label: 'Lookup', badge_class: 'ee-type-lookup', description: 'Links to: User' },
  { name: 'Active',      type_label: 'Yes/No', badge_class: 'ee-type-bool',   description: "Whether the item is active, or has been deleted." },
];

// ── Component ─────────────────────────────────────────────────────────────────

@Component({
  selector:   'attome-metadata-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [
    OwnerLayerBadgeComponent, FormsModule, RouterLink, TranslatePipe,
    FieldChangeDialogComponent, RecoveryArchiveComponent, BinSettingsComponent, FillRateBadgeComponent,
    FormulaEditorComponent,
  ],
  styleUrls:  ['../../../../../styles/admin-page.css', './entity-editor.component.css'],
  templateUrl: './entity-editor.component.html',
})
export class EntityEditorComponent implements OnInit {
  private readonly svc  = inject(AdminService);
  private readonly lang = inject(LangService);
  private readonly profiles = inject(DataProfileService);

  readonly id = input.required<string>();

  readonly entity  = signal<EntityDetail | null>(null);
  readonly loading = signal(true);
  readonly error   = signal<string | null>(null);
  /** L6-T7: each field's fill rate in the entity's latest data profile. */
  readonly fillRates = signal<Map<string, number>>(new Map());

  // Auto Value panel. `autoValuesLoaded` is separate from `!loading` so the
  // rules are fetched once, on first expand, and not again on every toggle.
  readonly showAutoValues    = signal(false);
  readonly autoValues        = signal<AutoValueRule[]>([]);
  readonly autoValuesLoading = signal(false);
  readonly autoValuesLoaded  = signal(false);
  readonly autoValueError    = signal<string | null>(null);

  readonly systemFields = SYSTEM_FIELDS;

  // Labels panel (M05 Phase 1, D-426) — same lazy-load-on-first-expand shape
  // as the Auto Value panel above, but editable: labels are admin-authored
  // per-locale overrides, not a development-time artifact.
  readonly showLabels    = signal(false);
  readonly labels        = signal<MetadataLabel[]>([]);
  readonly labelsLoading = signal(false);
  readonly labelsLoaded  = signal(false);
  readonly labelsError   = signal<string | null>(null);

  readonly newLabelTarget      = signal<string>('__entity__');
  readonly newLabelLocale      = signal('');
  readonly newLabelDisplayName = signal('');
  readonly newLabelDescription = signal('');
  readonly labelFormError      = signal<string | null>(null);
  readonly labelSaving         = signal(false);

  // Relationships panel (M01 Core P3 gap, D-455) — same lazy-load-on-
  // first-expand shape as Labels above.
  readonly showRelationships    = signal(false);
  readonly relationships        = signal<RelationshipDef[]>([]);
  readonly relationshipsLoading = signal(false);
  readonly relationshipsLoaded  = signal(false);
  readonly relationshipsError   = signal<string | null>(null);

  readonly allEntities = signal<EntityMeta[]>([]);

  readonly newRelName      = signal('');
  readonly newRelOtherEntity = signal('');
  readonly newRelRoleThis  = signal('');
  readonly newRelRoleOther = signal('');
  readonly newRelCascade   = signal<RelationshipCascade>('orphan');
  readonly relationshipFormError = signal<string | null>(null);
  readonly relationshipSaving    = signal(false);

  readonly cascadeOptions: readonly RelationshipCascade[] = ['orphan', 'restrict', 'cascade_deactivate'];

  // Field structure changes (Solution 7 Phase 2, D-788): one dialog at a
  // time, opened from a field card. Closing it reloads the entity when a
  // change was applied (renamed, deleted, retyped, choices changed).
  readonly dialogField = signal<AttributeMeta | null>(null);
  readonly dialogMode  = signal<FieldChangeMode>('rename');

  // Recovery archive (design §8.5) — rendered on first expand only.
  readonly showArchive = signal(false);

  ngOnInit(): void { this.load(); }

  // C-29 (M01 §7) — was a hardcoded `Record<XrmFieldType, string>` lookup;
  // now resolved through the i18n pipeline (`fieldTypes.*` catalog keys) so
  // this admin-only label is Arabic-first like the rest of the product.
  typeLabel(ft: XrmFieldType): string { return this.lang.translate(`fieldTypes.${ft}`); }

  /** A9-T4: the formula field whose editor is open, by id. */
  readonly editingFormula = signal<string | null>(null);

  /** A9-T4: a formula was saved; close its editor and reload the fields. */
  onFormulaSaved(): void {
    this.editingFormula.set(null);
    this.onFieldChangeClosed(true);
  }

  /** U9 (D-604) — a formula field's expression, shown on its card. */
  formulaExpression(options: unknown): string {
    const expr = (options as { expression?: unknown } | null | undefined)?.expression;
    return typeof expr === 'string' ? expr : '';
  }

  private load(): void {
    this.loading.set(true);
    this.svc.getEntity(this.id()).subscribe({
      next: e => { this.entity.set(e); this.loading.set(false); this.loadFillRates(e.logicalname); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  /** L6-T7: the hints are optional, so a failed profile read shows none. */
  private loadFillRates(entity: string): void {
    this.profiles.latest(entity).pipe(catchError(() => of(null))).subscribe(p => this.fillRates.set(fillRates(p)));
  }

  // ── Field structure changes (Solution 7 Phase 2) ──────────────────────────

  openFieldChange(field: AttributeMeta, mode: FieldChangeMode): void {
    this.dialogMode.set(mode);
    this.dialogField.set(field);
  }

  /** The dialog closed; reload the fields in place when something changed. */
  onFieldChangeClosed(changed: boolean): void {
    this.dialogField.set(null);
    if (!changed) return;
    this.svc.getEntity(this.id()).subscribe({
      next: e => this.entity.set(e),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Field names offered by the recovery-archive filter. */
  fieldNames(): string[] {
    return this.entity()?.attributes.map(a => a.logicalname) ?? [];
  }

  toggleArchive(): void { this.showArchive.update(v => !v); }

  // ── Auto Value ────────────────────────────────────────────────────────────
  //
  // Rules live in `autovalue`, an ordinary metadata entity, so this
  // panel is a thin editor over the generic record endpoints (AdminService's
  // listAutoValues/createAutoValue/…) rather than a second admin API. Loaded
  // lazily on first expand: most visits to this page are about fields, and an
  // entity with no rules should cost no request.

  toggleAutoValues(): void {
    const opening = !this.showAutoValues();
    this.showAutoValues.set(opening);
    if (opening && !this.autoValuesLoaded()) this.loadAutoValues();
  }

  private loadAutoValues(): void {
    const e = this.entity();
    if (!e) return;
    this.autoValuesLoading.set(true);
    this.autoValueError.set(null);
    this.svc.listAutoValues(e.logicalname).subscribe({
      next: rules => {
        this.autoValues.set(rules);
        this.autoValuesLoaded.set(true);
        this.autoValuesLoading.set(false);
      },
      error: (err: ApiError) => {
        this.autoValueError.set(err.message);
        this.autoValuesLoading.set(false);
      },
    });
  }

  /** Display name of an attribute, falling back to its logicalname. */
  fieldLabel(logicalname: string): string {
    return this.entity()?.attributes.find(a => a.logicalname === logicalname)?.name ?? logicalname;
  }

  resetLabel(scope: AutoValueResetScope): string {
    return RESET_SCOPE_LABELS[scope] ?? scope;
  }

  preview(r: AutoValueRule): string { return renderFormat(r.format, r.next_value, new Date()); }

  // ── Labels (M05 Phase 1, D-426) ───────────────────────────────────────────

  toggleLabels(): void {
    const opening = !this.showLabels();
    this.showLabels.set(opening);
    if (opening && !this.labelsLoaded()) this.loadLabels();
  }

  private loadLabels(): void {
    this.labelsLoading.set(true);
    this.labelsError.set(null);
    this.svc.listLabels(this.id()).subscribe({
      next: rows => {
        this.labels.set(rows);
        this.labelsLoaded.set(true);
        this.labelsLoading.set(false);
      },
      error: (err: ApiError) => {
        this.labelsError.set(err.message);
        this.labelsLoading.set(false);
      },
    });
  }

  /** Display text for a label row's target — the entity's own name, or
   * `"{Field label} field"`/`"{Field label}: {option}"` for the other two
   * kinds this editor supports. */
  labelTarget(l: MetadataLabel): string {
    const rest = l.object_ref.slice(this.entity()!.logicalname.length + 1);
    if (l.object_kind === 'entity') return 'Item name';
    if (l.object_kind === 'attribute') return `${this.fieldLabel(rest)} field`;
    const [attr, ...optionParts] = rest.split('.');
    return `${this.fieldLabel(attr)}: ${optionParts.join('.')}`;
  }

  addLabel(): void {
    this.labelFormError.set(null);
    const locale = this.newLabelLocale().trim();
    const displayName = this.newLabelDisplayName().trim();
    if (!/^[a-z]{2}(-[A-Z]{2})?$/.test(locale)) {
      this.labelFormError.set('Locale must look like "en" or "en-US".');
      return;
    }
    if (!displayName) {
      this.labelFormError.set('A translated name is required.');
      return;
    }
    const target = this.newLabelTarget();
    const body: MetadataLabelMutation = target === '__entity__'
      ? { object_kind: 'entity', locale, display_name: displayName, description: this.newLabelDescription().trim() || null }
      : { object_kind: 'attribute', attribute_logicalname: target, locale, display_name: displayName, description: this.newLabelDescription().trim() || null };

    this.labelSaving.set(true);
    this.svc.createLabel(this.id(), body).subscribe({
      next: row => {
        this.labels.update(rows => [...rows, row]);
        this.newLabelLocale.set('');
        this.newLabelDisplayName.set('');
        this.newLabelDescription.set('');
        this.labelSaving.set(false);
      },
      error: (err: ApiError) => {
        this.labelFormError.set(err.message);
        this.labelSaving.set(false);
      },
    });
  }

  deleteLabel(l: MetadataLabel): void {
    this.svc.deleteLabel(this.id(), l.id).subscribe({
      next: () => this.labels.update(rows => rows.filter(r => r.id !== l.id)),
      error: (err: ApiError) => this.labelsError.set(err.message),
    });
  }

  // ── Relationships (M01 Core P3 gap, D-455) ───────────────────────────────

  toggleRelationships(): void {
    const opening = !this.showRelationships();
    this.showRelationships.set(opening);
    if (opening && !this.relationshipsLoaded()) this.loadRelationships();
  }

  private loadRelationships(): void {
    const e = this.entity();
    if (!e) return;
    this.relationshipsLoading.set(true);
    this.relationshipsError.set(null);
    this.svc.listRelationships(e.logicalname).subscribe({
      next: rows => {
        this.relationships.set(rows);
        this.relationshipsLoaded.set(true);
        this.relationshipsLoading.set(false);
      },
      error: (err: ApiError) => {
        this.relationshipsError.set(err.message);
        this.relationshipsLoading.set(false);
      },
    });
    // Entity picker for "the other side" — loaded alongside, not gated
    // behind its own toggle: this panel is the only consumer.
    this.svc.listEntities().subscribe({ next: rows => this.allEntities.set(rows) });
  }

  /** This entity's own role label, oriented for display next to the
   * relationship's `name` — `role_a`/`role_b` per which side `entity()` is. */
  thisRoleLabel(r: RelationshipDef): string {
    const e = this.entity();
    return e && r.entity_a === e.logicalname ? r.role_b : r.role_a;
  }

  otherEntityLabel(r: RelationshipDef): string {
    const e = this.entity();
    return e && r.entity_a === e.logicalname ? r.entity_b : r.entity_a;
  }

  cascadeLabel(c: string): string { return cascadeLabelFor(c); }

  addRelationship(): void {
    const e = this.entity();
    if (!e) return;
    this.relationshipFormError.set(null);

    const name = this.newRelName().trim();
    const otherEntity = this.newRelOtherEntity();
    const roleThis = this.newRelRoleThis().trim();
    const roleOther = this.newRelRoleOther().trim();
    if (!name) { this.relationshipFormError.set('A relationship name is required.'); return; }
    if (!otherEntity) { this.relationshipFormError.set('Choose the other entity.'); return; }
    if (!roleThis || !roleOther) {
      this.relationshipFormError.set('Both role labels are required.');
      return;
    }

    // This entity is always submitted as `entity_a` — an arbitrary but
    // consistent choice; the API itself treats the two sides symmetrically
    // (see `RelationshipDef::other_side`), so which one lands in `entity_a`
    // vs `entity_b` has no behavioral effect.
    const body: CreateRelationshipBody = {
      name,
      entity_a: e.logicalname,
      entity_b: otherEntity,
      role_a: roleOther,
      role_b: roleThis,
      cascade: this.newRelCascade(),
    };

    this.relationshipSaving.set(true);
    this.svc.createRelationship(body).subscribe({
      next: row => {
        this.relationships.update(rows => [...rows, row]);
        this.newRelName.set('');
        this.newRelOtherEntity.set('');
        this.newRelRoleThis.set('');
        this.newRelRoleOther.set('');
        this.newRelCascade.set('orphan');
        this.relationshipSaving.set(false);
      },
      error: (err: ApiError) => {
        this.relationshipFormError.set(err.message);
        this.relationshipSaving.set(false);
      },
    });
  }

  deleteRelationship(r: RelationshipDef): void {
    this.svc.deleteRelationship(r.id).subscribe({
      next: () => this.relationships.update(rows => rows.filter(row => row.id !== r.id)),
      error: (err: ApiError) => this.relationshipsError.set(err.message),
    });
  }
}
