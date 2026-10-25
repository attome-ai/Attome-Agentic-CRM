import {
  computed, DestroyRef, Directive, effect, inject, Injector, input, OnInit, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, FormGroup } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiError, CommandRegistry, LangService, MetadataVersion, VersionConflictState } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { firstValueFrom } from 'rxjs';
import { BusinessRuleClient, ChoiceOptions, EntitySchema, FieldSchema } from '@attome/xrm';
import { fieldKindResolver } from '../business-rules/business-rule-condition';
import {
  computeFieldPolicies, fieldErrorsFromApiError, isEmptyFieldValue, reconcileAllowed, writeWarnings,
  type FieldLockState, type FieldRuleMessage, type RuleWriteWarning,
} from '../business-rules/field-policy';
import { withGoldenTab } from '../record-tabs/record-tabs';
import { EntityRecordResponse, EntityService } from '../services/entity.service';
import { entityFormRoute, entityListRoute } from '../services/entity-url.utils';
import { RecordChange, RecordChangeNotifier } from '../services/record-change-notifier.service';
import { DuplicatesService } from '@attome/xrm/core/admin/data';
import { DuplicateNotice, duplicateWarningsOf } from '../duplicate-banner/duplicate-notice';
import { ConflictChoices } from '../conflict-dialog/conflict-dialog.component';
import { fieldValidators } from '../field/field-checks';

/**
 * How long the post-save tick holds before the submit button returns to its
 * idle "Update" label. Long enough to be read after the eye moves back to the
 * button, short enough that the form isn't left claiming a save that is by
 * then several edits old.
 */
export const SAVED_CONFIRMATION_MS = 1500;

const EMPTY_LOCKS: ReadonlyMap<string, FieldLockState> = new Map();
const EMPTY_ALLOWED: ReadonlyMap<string, readonly string[]> = new Map();

/** Same fields with the same allowed values in the same order. */
function sameAllowed(
  a: ReadonlyMap<string, readonly string[]>, b: ReadonlyMap<string, readonly string[]>,
): boolean {
  if (a.size !== b.size) return false;
  for (const [field, values] of a) {
    const other = b.get(field);
    if (!other || other.length !== values.length || other.some((v, i) => v !== values[i])) return false;
  }
  return true;
}
const NO_RULE_MESSAGES: readonly FieldRuleMessage[] = [];

/** Value equality for a reset decision: `undefined` equals `null`; lists and objects by content. */
function sameValue(a: unknown, b: unknown): boolean {
  const x = a === undefined ? null : a;
  const y = b === undefined ? null : b;
  if (x === y) return true;
  if (typeof x === 'object' && typeof y === 'object' && x !== null && y !== null) {
    return JSON.stringify(x) === JSON.stringify(y);
  }
  return false;
}

export interface XrmFormTabDef {
  id: string;
  label: string;
  icon: string;
}

/**
 * The one abstract base every xrm form extends — the generic metadata-driven
 * dispatcher (`EntityFormComponent`) and every hand-written per-entity form
 * (user, role, workflow-definition, and the per-built-in-entity forms) alike.
 * Previously this logic was split three ways (a `FormBase` directive owning
 * only request-lifecycle state, an `EngineFormBase` extending it with
 * schema/form/save/cancel, and `EntityFormComponent` independently
 * reimplementing that same schema/form/save/cancel logic plus its own tab
 * handling) — merged here so there is exactly one implementation of each
 * concern: data fetching, field validation, save/cancel button state, and
 * tab navigation.
 *
 * Subclass pattern:
 *
 *   @Component({ template: `...` })
 *   export class UserFormComponent extends EngineFormBase {
 *     protected override defineTabs(): XrmFormTabDef[] { return [...]; }
 *   }
 *
 * `name`/`id` are passed by `EntityRouterComponent` (routed entity logicalname
 * and record id; `id` null = create mode). The base class handles schema
 * loading, record GET/POST/PATCH, save-conflict/reload, dirty tracking, and
 * keyboard tab navigation. Subclasses define the template — sections, field
 * groups, custom validation, which tabs exist.
 */
@Directive()
export abstract class EngineFormBase implements OnInit {
  // ── Router inputs ─────────────────────────────────────────────────────────
  readonly name = input.required<string>();            // entity logicalname from router
  readonly id   = input<string | null>(null);           // record id (null = create mode)

  // ── Request lifecycle state ────────────────────────────────────────────────
  readonly loading = signal(true);
  readonly saving  = signal(false);
  readonly error   = signal<string | null>(null);

  /** True while the post-save confirmation tick is showing. */
  readonly justSaved = signal(false);
  private savedTimer: ReturnType<typeof setTimeout> | null = null;

  // ── Shared form state (signal-based so templates react) ────────────────────
  readonly schema = signal<EntitySchema | null>(null);
  readonly form   = signal<FormGroup>(new FormGroup({}));
  readonly isEdit = computed(() => !!this.id());

  /**
   * Mirrors `form().dirty` as a signal. A `FormGroup`'s own `dirty` is a plain
   * property with no change notification, so a `computed()` reading it would
   * never recompute and the submit button's disabled state would never track
   * the user's edits — hence the explicit mirror, fed from `valueChanges`.
   */
  readonly dirty = signal(false);

  /**
   * Update is disabled while a save is in flight and while there is nothing to
   * save. The pristine gate is edit-only: a create form is pristine until the
   * operator types, but an entity whose fields are all optional or
   * auto-generated is legitimately creatable from an untouched form, so
   * gating create the same way would make those records unreachable.
   */
  readonly canSave = computed(() => !this.saving() && (!this.isEdit() || this.dirty()));

  /** Set when a save's field validation fails client-side (not the same as a server error banner). */
  readonly validationError = signal(false);
  /** Set on a 409 from a stale `row_version` — resolved via `reload()`, not a generic error banner. */
  readonly conflict  = signal(false);
  readonly reloading = signal(false);
  /**
   * A16-T3: what the last 409 said changed, while the conflict dialog is
   * open; `null` when the body named nothing or the dialog was closed.
   */
  readonly conflictDetails = signal<VersionConflictState | null>(null);
  /**
   * A16-T3: the attributes another user changed that the last save was
   * merged over (`merged_over`), for a short notice. Empty otherwise.
   */
  readonly mergedOver = signal<readonly string[]>([]);
  /**
   * A15-T4: the last save matched existing records under a duplicate rule —
   * refused (`block`, or `allow_with_reason` without a reason) or saved with
   * a warning. Shown by `xrm-duplicate-banner`.
   */
  readonly duplicateNotice = signal<DuplicateNotice | null>(null);

  // ── Business rules (D-789 section 5, D-791 rule 6) ───────────────────────
  /**
   * The caller's client-side business rules, delivered with the schema
   * (already filtered to this user's audience by the server). Lock and
   * field-attached error policies only; `set_value` policies and advanced
   * conditions are server-only.
   */
  readonly businessRules = computed<readonly BusinessRuleClient[]>(
    () => this.schema()?.business_rules ?? []);

  private readonly ruleFieldKinds = computed(() => fieldKindResolver(this.schema()?.fields ?? []));

  /**
   * The record as it would be saved: the loaded record overlaid with the
   * form's raw value (disabled controls included), refreshed on every
   * `valueChanges`. Conditions evaluate against this.
   */
  readonly recordValue = signal<Readonly<Record<string, unknown>>>({});

  private readonly ruleOutcome = computed(() => computeFieldPolicies(
    this.businessRules(), this.recordValue(), this.ruleFieldKinds()));

  /** Field to the lock the rules put on it for this user (`hidden` beats `disabled`). */
  readonly fieldPolicies = computed<ReadonlyMap<string, FieldLockState>>(() =>
    this.businessRules().length ? this.ruleOutcome().locks : EMPTY_LOCKS);

  /** Field to its field-attached `error` policies firing now (shown live, never blocking). */
  readonly fieldErrors = computed(() => this.ruleOutcome().errors);

  /** A6-T2: field to the values its `allowed_values` rules allow now. */
  readonly allowedValues = computed(
    () => this.businessRules().length ? this.ruleOutcome().allowed : EMPTY_ALLOWED,
    // Unchanged on a keystroke that changes no rule's outcome, so the effect
    // below (and the change-detection tick it schedules) does not re-run.
    { equal: sameAllowed });

  /** A6-T2: field to the value a rule just cleared from it, for undo. */
  readonly clearedValues = signal<ReadonlyMap<string, unknown>>(new Map());

  /** Field to the last save's refusal naming it (`field_locked*`, `rule_violation`). */
  readonly serverFieldErrors = signal<ReadonlyMap<string, string>>(new Map());

  /** D-791 rule 6: the `warning` policies the last successful save returned. */
  readonly saveWarnings = signal<readonly RuleWriteWarning[]>([]);

  /** Controls this base disabled for a lock (never one a subclass disabled itself). */
  private readonly policyLocked = new Set<string>();
  /** A create form's values as built: the "stored" value a locked control resets to. */
  private initialValues: Record<string, unknown> = {};

  // ── Tabs ──────────────────────────────────────────────────────────────────
  /** Override to declare this form's tabs; a single implicit "General" tab by default (no tab UI needed). */
  protected defineTabs(): XrmFormTabDef[] {
    return [{ id: 'general', label: 'General', icon: 'las la-list-alt' }];
  }
  readonly tabs = computed<XrmFormTabDef[]>(() => withGoldenTab(
    this.defineTabs(),
    this.schema()?.is_master === true,
    key => this.formInjector.get(LangService).translate(key),
  ));
  readonly activeTab = signal('general');

  // ── Services ──────────────────────────────────────────────────────────────
  protected readonly svc    = inject(EntityService);
  protected readonly fb     = inject(FormBuilder);
  protected readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);
  private readonly recordChanges = inject(RecordChangeNotifier);
  /** Resolves the dialog and language services only when Duplicate needs them. */
  private readonly formInjector = inject(Injector);

  // `protected`, not `private`: a subclass that calls a bespoke, non-generic
  // write endpoint of its own (e.g. `DashboardEditorComponent`'s lifecycle
  // transitions) still needs the row_version the base class's own GET/save
  // cycle already tracks, rather than re-fetching it or — worse — omitting
  // it and letting a required-field deserialization error be the first sign
  // (found while wiring `DashboardEditorComponent` through `DashboardService`,
  // R-10).
  protected record: EntityRecordResponse | null = null;

  constructor() {
    // The save-confirmation timer outlives a form the operator navigates away
    // from mid-confirmation; without this it would fire against a destroyed
    // component.
    this.destroyRef.onDestroy(() => this.clearSavedTimer());
    // Y8-T8: a newer metadata version while the form is open.
    this.formInjector.get(MetadataVersion).changes
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(() => this.modelChanged.set(true));
    // B10-T1: this record's actions come first in the command palette while
    // the form is open.
    this.destroyRef.onDestroy(this.formInjector.get(CommandRegistry).register(
      { id: 'record.save', labelKey: 'xrmForm.cmdSave', icon: 'las la-save', context: true, run: () => this.save() },
      { id: 'record.duplicate', labelKey: 'xrmForm.cmdDuplicate', icon: 'las la-copy', context: true,
        run: () => void this.duplicate() },
      { id: 'record.reload', labelKey: 'xrmForm.cmdReload', icon: 'las la-sync', context: true, run: () => this.reload() },
    ));
    // Reset to the first tab whenever the routed entity changes, so a
    // persisted instance switching straight from one entity's form to
    // another's (the generic dispatcher's `NgComponentOutlet` reuse case)
    // never leaves a tab selected that the new entity doesn't have.
    effect(() => {
      this.name();
      untracked(() => this.activeTab.set(this.tabs()[0]?.id ?? 'general'));
    });
    this.recordChanges.changes
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe(change => this.onServerRecordChange(change));
    // D-789 section 5: apply the business-rule locks live. A locked control
    // is disabled (so `fg.value`, and therefore a save, never carries it) and
    // reset to its stored value; an unlocked one is re-enabled.
    effect(() => {
      const locks = this.fieldPolicies();
      const fg = this.form();
      untracked(() => this.applyFieldLocks(fg, locks));
    });
    // A6-T2: once the person changes something (or on a new record), a
    // value the rules no longer allow is cleared (with undo), and an empty
    // field with one allowed value is filled. A loaded record is left as
    // stored until then; the server refuses a value that does not fit.
    effect(() => {
      const allowed = this.allowedValues();
      const fg = this.form();
      untracked(() => this.applyAllowedValues(fg, allowed));
    });
  }

  private applyAllowedValues(fg: FormGroup, allowed: ReadonlyMap<string, readonly string[]>): void {
    if (!fg.dirty && this.id()) return;
    for (const [field, values] of allowed) {
      const ctrl = fg.get(field);
      if (!ctrl || ctrl.disabled) continue;
      const action = reconcileAllowed(ctrl.value, values);
      if (action.kind === 'clear') {
        const previous: unknown = ctrl.value;
        ctrl.setValue(Array.isArray(previous) ? [] : null);
        ctrl.markAsDirty();
        this.clearedValues.update(m => new Map(m).set(field, previous));
      } else if (action.kind === 'fill') {
        ctrl.setValue(action.value);
        ctrl.markAsDirty();
      }
    }
  }

  /** A6-T2: puts back the value a rule cleared from `field`. */
  undoClear(field: string): void {
    const cleared = this.clearedValues();
    if (!cleared.has(field)) return;
    const previous = cleared.get(field);
    const next = new Map(cleared);
    next.delete(field);
    this.clearedValues.set(next);
    const ctrl = this.form().get(field);
    if (ctrl) {
      ctrl.setValue(previous);
      ctrl.markAsDirty();
    }
  }

  /**
   * U18 — a widget in this form changed the record on the server outside the
   * form's own save (a file version restore). Re-GET it so the next save
   * carries the new `row_version` instead of 409-ing, and show the server's
   * value for exactly the changed fields. The operator's other unsaved edits
   * are left alone and the form's dirty state is not touched.
   */
  private onServerRecordChange(change: RecordChange): void {
    const id = this.id();
    if (!id || change.recordId !== id || change.entityName !== this.entityLogicalName) return;
    this.svc.get(this.entityLogicalName, id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => {
        if (this.id() !== id) return;
        this.record = r;
        this.loadedVersion.set(r.row_version);
        const fg = this.form();
        for (const field of change.fields) {
          const ctrl = fg.get(field);
          if (ctrl && Object.prototype.hasOwnProperty.call(r.data, field)) {
            ctrl.setValue(r.data[field], { emitEvent: true });
            ctrl.markAsPristine();
          }
        }
        this.dirty.set(fg.dirty);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /**
   * The entity this form edits. Defaults to the routed `name` input —
   * correct for every hand-written per-entity form (each is only ever
   * registered against, and therefore only ever routed for, its own
   * logicalname) and for the generic dispatcher (whose "entity" genuinely is
   * whatever the route says). Override only if a form legitimately needs to
   * edit a different entity than the one it was routed for.
   */
  protected get entityLogicalName(): string {
    return this.name();
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  ngOnInit(): void {
    this.svc.getSchema(this.entityLogicalName).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: schema => {
        this.schema.set(schema);
        this.onSchemaLoaded(schema);
        const fg = this.buildFormGroup(schema);
        this.policyLocked.clear();
        this.initialValues = { ...(fg.getRawValue() as Record<string, unknown>) };
        this.form.set(fg);
        this.syncRecordValue(fg);
        this.trackDirtyState(fg);
        if (this.id()) this.loadRecord();
        else {
          this.loading.set(false);
          this.applyDefaults(fg);
        }
      },
      error: () => this.loading.set(false),
    });
  }

  /** Y8-T8: the entity's design changed on the server while this form was open. */
  readonly modelChanged = signal(false);

  /** A16-T4: the `row_version` this form loaded or last saved. */
  readonly loadedVersion = signal<number | null>(null);

  /** B7-T3: whether a copy is being made. */
  readonly duplicating = signal(false);

  /**
   * B7-T3: copies this record and opens the copy. When it has child records,
   * asks once whether to copy them too.
   */
  async duplicate(): Promise<void> {
    const id = this.id();
    if (!id || this.duplicating()) return;
    this.duplicating.set(true);
    let children: { entity: string; field: string }[] = [];
    if (typeof this.svc.childRecords === 'function') {
      const found = await firstValueFrom(this.svc.childRecords(this.entityLogicalName, id))
        .then(page => page.items)
        .catch(() => []);
      if (found.length) {
        const lang = this.formInjector.get(LangService);
        const copyThem = await this.formInjector.get(DialogService).confirm({
          message: lang.translate('xrmForm.duplicateWithChildren', {
            details: found.map(c => `${c.entity} (${c.count})`).join(', '),
          }),
          confirmText: lang.translate('xrmForm.duplicateCopyChildren'),
          cancelText: lang.translate('xrmForm.duplicateRecordOnly'),
        });
        if (copyThem) children = found.map(c => ({ entity: c.entity, field: c.field }));
      }
    }
    this.svc.clone(this.entityLogicalName, id, children).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: copy => {
        this.duplicating.set(false);
        if (copy.id) {
          void this.router.navigate(entityFormRoute(this.entityLogicalName), { queryParams: { id: copy.id } });
        }
      },
      error: () => this.duplicating.set(false),
    });
  }

  /**
   * A28-T2: a new record starts with its attributes' defaults
   * (`GET /api/v1/{entity}/new`), filling only controls still empty. A host
   * whose entity service cannot answer (a form test's stub) keeps the blanks.
   */
  private applyDefaults(fg: FormGroup): void {
    if (typeof this.svc.newDefaults !== 'function') return;
    this.svc.newDefaults(this.entityLogicalName).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: values => {
        for (const [field, value] of Object.entries(values)) {
          const control = fg.get(field);
          if (control && (control.value === null || control.value === undefined || control.value === '')) {
            control.setValue(value);
          }
        }
      },
      error: () => undefined,
    });
  }

  /** Hook — override to react when schema arrives (e.g. add cross-field validators). */
  protected onSchemaLoaded(_schema: EntitySchema): void {}

  /**
   * Hook — called with the server's copy of the record every time the base
   * class receives one: the initial GET, a `reload()`, and a successful save.
   * `record` itself is a plain field (no change notification), so a subclass
   * that renders server-computed values — the ticket form's SLA badge reads
   * `resolution_due_at`/`sla_breached`, which the operator never edits —
   * mirrors what it needs into a signal here.
   */
  protected onRecordLoaded(_record: EntityRecordResponse): void {}

  /**
   * Builds a FormGroup from schema fields. Override to customise validators
   * or add synthetic controls.
   */
  protected buildFormGroup(schema: EntitySchema): FormGroup {
    const controls: Record<string, unknown[]> = {};
    for (const f of schema.fields) {
      let def: unknown = null;
      if (f.name === 'is_active') {
        // The platform's soft-delete flag, registered as an ordinary attribute
        // on some entities. A new record is live by definition, so `null` —
        // which renders the switch off — would show the opposite of what the
        // create actually produces. The backend no longer accepts the column
        // from an insert body at all, so this is purely about the control
        // matching the resulting record; in edit mode `patchValue` overwrites
        // it with the record's own value.
        def = true;
      } else if (f.field_type === 'choice') {
        const opts = f.options as ChoiceOptions | null;
        if (opts?.multi) def = [];
      }
      // A related grid opens a create form with its locked parent lookup in
      // the query string. Only schema-known fields are considered, and edit
      // forms ignore these defaults completely (loadRecord's patchValue below
      // overwrites them).
      if (!this.id()) {
        const supplied = this.router.parseUrl(this.router.url).queryParamMap.get(f.name);
        if (supplied !== null) def = supplied;
      }
      // U9 (D-604): a formula is computed by the server on every write and a
      // written value is refused (422). A disabled control keeps its loaded
      // value for display but is left out of `FormGroup.value`, so it is
      // never sent.
      if (f.field_type === 'formula') {
        controls[f.name] = [{ value: def, disabled: true }];
        continue;
      }
      // A3-T7: the server's own checks (required, pattern, format, range),
      // shown under the field as the person types.
      controls[f.name] = [def, fieldValidators(f)];
    }
    return this.fb.group(controls);
  }

  /**
   * Keeps `dirty` in step with the form and drops the "Saved" tick the moment
   * there are unsaved changes again. `valueChanges` covers every user edit;
   * programmatic writes (`patchValue` on load and after a save) also emit, but
   * leave `fg.dirty` false, so reading the flag rather than assuming "changed
   * means dirty" is what makes a freshly-loaded record read as pristine.
   */
  private trackDirtyState(fg: FormGroup): void {
    this.dirty.set(fg.dirty);
    fg.valueChanges.pipe(takeUntilDestroyed(this.destroyRef)).subscribe(() => {
      this.syncRecordValue(fg);
      this.dirty.set(fg.dirty);
      if (fg.valid) this.validationError.set(false);
      if (fg.dirty) this.clearSaved();
    });
  }

  /** Refreshes `recordValue` from the loaded record and the form's raw value. */
  private syncRecordValue(fg: FormGroup = this.form()): void {
    const stored = (this.record?.data ?? {}) as Record<string, unknown>;
    this.recordValue.set({ ...stored, ...(fg.getRawValue() as Record<string, unknown>) });
  }

  /** The value a locked control holds: the record's stored value (edit) or the built default (create). */
  private storedValue(name: string): unknown {
    if (this.record) {
      const data = this.record.data as Record<string, unknown>;
      return Object.prototype.hasOwnProperty.call(data, name) ? data[name] : null;
    }
    return this.initialValues[name] ?? null;
  }

  private applyFieldLocks(fg: FormGroup, locks: ReadonlyMap<string, FieldLockState>): void {
    let reset = false;
    for (const name of locks.keys()) {
      const ctrl = fg.get(name);
      if (!ctrl) continue;
      const stored = this.storedValue(name);
      if (!sameValue(ctrl.value, stored)) {
        ctrl.setValue(stored, { emitEvent: false });
        reset = true;
      }
      if (ctrl.enabled) {
        ctrl.disable({ emitEvent: false });
        this.policyLocked.add(name);
      }
    }
    for (const name of [...this.policyLocked]) {
      if (locks.has(name)) continue;
      this.policyLocked.delete(name);
      const ctrl = fg.get(name);
      // A formula stays disabled whatever the rules say (U9, D-604).
      if (ctrl && this.schemaField(name)?.field_type !== 'formula') ctrl.enable({ emitEvent: false });
    }
    if (reset) this.syncRecordValue(fg);
  }

  private schemaField(name: string): FieldSchema | undefined {
    return this.schema()?.fields.find(f => f.name === name);
  }

  private loadRecord(): void {
    this.svc.get(this.entityLogicalName, this.id()!).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => {
        this.record = r;
        this.loadedVersion.set(r.row_version);
        this.form().patchValue(r.data);
        this.onRecordLoaded(r);
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loading.set(false);
      },
    });
  }

  /**
   * Re-GETs the record to resolve a version conflict — never overwrites the
   * operator's in-progress edits on its own; `save()`'s conflict branch below
   * leaves the form as-is and the operator chooses when to discard them by
   * calling this.
   */
  reload(): void {
    if (!this.id()) return;
    this.reloading.set(true);
    this.svc.get(this.entityLogicalName, this.id()!).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => {
        this.record = r;
        this.loadedVersion.set(r.row_version);
        this.form().patchValue(r.data);
        this.onRecordLoaded(r);
        this.conflict.set(false);
        this.conflictDetails.set(null);
        this.reloading.set(false);
      },
      error: (e: ApiError) => {
        this.reloading.set(false);
        this.error.set(e.message);
      },
    });
  }

  // ── Save-lifecycle helpers ───────────────────────────────────────────────
  protected beginSave(): void {
    this.saving.set(true);
    this.error.set(null);
    this.serverFieldErrors.set(new Map());
    this.clearedValues.set(new Map());
    this.saveWarnings.set([]);
    this.duplicateNotice.set(null);
    this.mergedOver.set([]);
  }

  protected completeSave(): void {
    this.saving.set(false);
  }

  /** Shows the tick, then falls back to the idle button on its own. */
  protected confirmSaved(): void {
    this.clearSavedTimer();
    this.justSaved.set(true);
    this.savedTimer = setTimeout(() => {
      this.savedTimer = null;
      this.justSaved.set(false);
    }, SAVED_CONFIRMATION_MS);
  }

  /**
   * Drops the tick immediately — the record has been edited again, or another
   * save has started, so the confirmation no longer describes the form.
   */
  protected clearSaved(): void {
    this.clearSavedTimer();
    this.justSaved.set(false);
  }

  private clearSavedTimer(): void {
    if (this.savedTimer !== null) {
      clearTimeout(this.savedTimer);
      this.savedTimer = null;
    }
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  /** A15-T4: saves again with the reason an `allow_with_reason` rule asks for. */
  saveWithDuplicateReason(reason: string): void {
    const trimmed = reason.trim();
    if (trimmed) this.save(trimmed);
  }

  /**
   * A16-T3: the conflict dialog's answer. Keeps every value on screen, takes
   * the newer row version, and saves again: an attribute marked "theirs" is
   * left out so the server keeps their value (shown once the save answers),
   * one marked "mine" is sent as typed.
   */
  resolveConflict(choices: ConflictChoices): void {
    const details = this.conflictDetails();
    if (!details || !this.record) return;
    this.record = { ...this.record, row_version: details.currentVersion };
    this.conflictDetails.set(null);
    const theirs = Object.keys(choices).filter(name => choices[name] === 'theirs');
    this.save(undefined, theirs);
  }

  /** A16-T3: closes the conflict dialog; the typed values stay as they are. */
  dismissConflict(): void {
    this.conflictDetails.set(null);
  }

  /**
   * A16-T3: the attributes an update sends: those whose value differs from
   * the record as loaded, so an automatic merge (`If-Match-Merge`) only
   * conflicts on what this person changed. All of them when nothing differs,
   * as before.
   */
  private changedValues(data: Record<string, unknown>, leaveOut: readonly string[]): Record<string, unknown> {
    const stored = (this.record?.data ?? {}) as Record<string, unknown>;
    const same = (a: unknown, b: unknown) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);
    const changed: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(data)) {
      if (leaveOut.includes(name)) continue;
      if (!same(value, stored[name])) changed[name] = value;
    }
    if (Object.keys(changed).length) return changed;
    const all = { ...data };
    for (const name of leaveOut) delete all[name];
    return all;
  }

  save(duplicateReason?: string, takeTheirs: readonly string[] = []): void {
    const fg = this.form();
    if (!this.canSave()) return;
    if (fg.invalid) {
      fg.markAllAsTouched();
      this.validationError.set(true);
      return;
    }
    this.validationError.set(false);
    this.beginSave();
    this.conflict.set(false);
    this.clearSaved();

    const data = fg.value as Record<string, unknown>;
    const id = this.id();
    let req$;
    if (this.isEdit() && id) {
      // A16-T3: every update may merge over attributes it does not send.
      const options = duplicateReason
        ? { duplicateReason, mergeAttributes: true }
        : { mergeAttributes: true };
      req$ = this.svc.update(
        this.entityLogicalName, id, this.changedValues(data, takeTheirs), this.record?.row_version, options);
    } else {
      req$ = duplicateReason
        ? this.svc.create(this.entityLogicalName, data, { duplicateReason })
        : this.svc.create(this.entityLogicalName, data);
    }

    req$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: r => {
        // `r` carries the row_version the server just assigned. Keeping it is
        // what lets an update stay on the page: the next save sends the
        // current version instead of the one this form loaded with, which
        // would otherwise conflict on the second consecutive save.
        this.record = r;
        this.loadedVersion.set(r.row_version);
        // A16-T3: what the other writer changed (left to them, or merged
        // over) now shows their value, so the next save does not send the
        // old one back over it.
        const theirs = [...takeTheirs, ...(r.merged_over ?? [])];
        if (theirs.length) {
          const stored = r.data as Record<string, unknown>;
          this.form().patchValue(Object.fromEntries(theirs.map(name => [name, stored[name]])));
        }
        this.mergedOver.set(r.merged_over ?? []);
        this.completeSave();
        // D-791 rule 6: warnings never block; the save went through.
        this.saveWarnings.set(writeWarnings(r));
        this.duplicateNotice.set(duplicateWarningsOf(r));
        this.onRecordLoaded(r);
        this.onSaved(r);
      },
      error: (e: ApiError) => {
        this.completeSave();
        // Preserve the user's in-progress edits — never overwrite the form on
        // a version conflict; the operator chooses when to discard them via
        // `reload()`.
        if (e.kind === 'version_conflict') {
          this.conflict.set(true);
          // A16-T3: the dialog lists what changed when the server said so.
          const details = e.versionConflict;
          this.conflictDetails.set(details && details.changedAttributes.length ? details : null);
        }
        else if (e.duplicates) this.onDuplicateRefusal(data, e.duplicates);
        else {
          this.error.set(e.message);
          // D-789 sections 3.4/3.5: a `field_locked*` or field-attached
          // `rule_violation` refusal is also shown under its field (it covers
          // a rule that changed after the form loaded).
          // A3-T7: every failing field of a 422 under its field, in the
          // user's language where the code is known.
          this.serverFieldErrors.set(fieldErrorsFromApiError(e, (code, message) => {
            const key = `xrmForm.fieldError.${code}`;
            const text = this.formInjector.get(LangService).translate(key);
            return text === key ? message : text;
          }));
        }
      },
    });
  }

  /**
   * A15-T4: a save refused as a likely duplicate. The refusal does not say
   * whether a reason would let it through, so the check route (which writes
   * nothing) is asked what saving these values would do.
   */
  private onDuplicateRefusal(data: Record<string, unknown>, found: NonNullable<ApiError['duplicates']>): void {
    const notice: DuplicateNotice = { refused: true, action: 'block', matches: found.matches, hidden: found.hidden };
    this.duplicateNotice.set(notice);
    // Resolved here, not at construction: most forms never meet a refusal.
    this.formInjector.get(DuplicatesService).check(this.entityLogicalName, data, this.id()).subscribe({
      next: r => {
        if (this.duplicateNotice() === notice && r.action) this.duplicateNotice.set({ ...notice, action: r.action });
      },
      error: () => undefined,
    });
  }

  /**
   * Called after a successful save. Both create and update stay on the
   * record — navigating to the list on every save threw away the operator's
   * context and gave no confirmation beyond the page changing, indistinguishable
   * from a Cancel. `record` is replaced above before this runs, so the next
   * save carries the `row_version` the server just returned rather than a
   * stale one.
   *
   * A **create** additionally swaps the route to the new record's own form
   * (`id` moves from absent to the new id) — the form has no record id yet
   * because it comes from the route, so this is what turns the "New" form
   * into the saved record's form instead of leaving it pointed at a create
   * that already happened (which would insert a duplicate on the next save).
   *
   * `confirmSaved` shows the tick and hands the button back to "Update" after
   * `SAVED_CONFIRMATION_MS` — the button stays disabled at that point, since
   * a pristine record still has nothing to save.
   */
  protected onSaved(record: EntityRecordResponse): void {
    if (!this.isEdit()) {
      this.router.navigate(entityFormRoute(this.entityLogicalName), { queryParams: { id: record.id } });
    }
    const fg = this.form();
    fg.patchValue(record.data);
    fg.markAsPristine();
    this.dirty.set(false);
    this.confirmSaved();
  }

  cancel(): void {
    this.router.navigate(entityListRoute(this.entityLogicalName));
  }

  /** The list route as a link target, for a breadcrumb rendered as a real anchor. */
  listLink(): string[] {
    return entityListRoute(this.entityLogicalName);
  }

  // ── Tab navigation ────────────────────────────────────────────────────────

  selectTab(tab: string): void {
    this.activeTab.set(tab);
  }

  /**
   * ArrowRight/Left/Home/End cycling through `tabs()`, refocusing the
   * corresponding DOM tab button by index. Bind `(keydown)` on each
   * individual tab button (not the `role="tablist"` wrapper) — the buttons
   * are expected to be direct children of that wrapper, so
   * `event.currentTarget`'s parent is where the `[role="tab"]` query below
   * finds its siblings.
   */
  onTabKeydown(event: KeyboardEvent): void {
    const list = this.tabs();
    const current = list.findIndex(t => t.id === this.activeTab());
    let next: number;
    if (event.key === 'ArrowRight') next = (current + 1) % list.length;
    else if (event.key === 'ArrowLeft') next = (current - 1 + list.length) % list.length;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = list.length - 1;
    else return;

    event.preventDefault();
    this.activeTab.set(list[next].id);
    const tabButton = event.currentTarget as HTMLElement;
    tabButton.parentElement?.querySelectorAll<HTMLElement>('[role="tab"]')[next]?.focus();
  }

  // ── Template helpers ──────────────────────────────────────────────────────

  /** True when a control for `name` exists in the current form. */
  hasCtrl(name: string): boolean {
    return !!this.form().get(name);
  }

  /** Returns the display label for a field from the loaded schema. */
  label(name: string): string {
    return this.schema()?.fields.find(f => f.name === name)?.display_name ?? name;
  }

  // ── Business-rule helpers (D-789 section 5) ──────────────────────────────

  /** The lock a business rule puts on `name` for this user, or `null`. */
  fieldLock(name: string): FieldLockState | null {
    return this.fieldPolicies().get(name) ?? null;
  }

  /** `hidden`: not shown and not editable. */
  isHidden(name: string): boolean {
    return this.fieldLock(name)?.effect === 'hidden';
  }

  /** `disabled`: shown read-only, not editable. */
  isDisabled(name: string): boolean {
    return this.fieldLock(name)?.effect === 'disabled';
  }

  /** The rule that locks `name` (display name, else name), or `null`. */
  lockReason(name: string): string | null {
    return this.fieldLock(name)?.ruleName ?? null;
  }

  /** Field-attached `error` policies firing on the current values. */
  ruleMessages(name: string): readonly FieldRuleMessage[] {
    return this.fieldErrors().get(name) ?? NO_RULE_MESSAGES;
  }

  /** A required field a rule locks and that is empty: saving fails naming field and rule (section 3.4). */
  isRequiredLocked(name: string): boolean {
    return this.required(name) && this.fieldLock(name) !== null
      && isEmptyFieldValue(this.recordValue()[name]);
  }

  /** Whether a specific field is required per schema. */
  required(name: string): boolean {
    return this.schema()?.fields.find(f => f.name === name)?.is_required ?? false;
  }

  /**
   * Allowed values of a `choice` field, straight from the loaded schema —
   * so a subclass template renders the options the backend will actually
   * accept, and a metadata edit needs no template change. Empty array for a
   * missing field or any non-choice type.
   */
  choices(name: string): string[] {
    const f = this.schema()?.fields.find(f => f.name === name);
    if (f?.field_type !== 'choice') return [];
    return (f.options as ChoiceOptions | null)?.choices ?? [];
  }

  /**
   * Every schema field, sorted for display — the shape a form that renders
   * its fields generically via `<attome-field-input>` (the generic dispatcher,
   * and most per-entity forms whose fields don't need bespoke controls) wants
   * as-is. Override `filterFields` to drop a field this form's UI
   * deliberately hides (e.g. a self-referencing lookup with no supported
   * picker workflow) — the field stays real and writable in metadata and the
   * API, only the rendered list changes.
   */
  readonly sortedFields = computed<FieldSchema[]>(() => {
    const fields = this.schema()?.fields ?? [];
    return this.filterFields([...fields]).sort((a, b) => a.sort_order - b.sort_order);
  });

  protected filterFields(fields: FieldSchema[]): FieldSchema[] {
    return fields;
  }
}
