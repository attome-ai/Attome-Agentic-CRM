import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { ExpressionEditorComponent } from '@attome/xrm/core/admin/expression-editor';
import { LangService, TranslatePipe } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import type { ApiError } from '@attome/base';
import {
  AdminService, StateModelsService,
  type AttributeMeta, type EntityMeta,
  type StateModelDetail, type StateModelListItem, type StateTransition,
} from '@attome/xrm/core/admin/data';
import { GovernanceNavComponent } from '../nav/governance-nav.component';
import { StateDiagramComponent } from '../state-diagram/state-diagram.component';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

/** The editable part of a transition row, edge included. Actions are
 * edited as one comma-separated string and split on save. */
export interface TransitionDraft {
  from_state:         string;
  to_state:           string;
  name:               string;
  required_privilege: string;
  guard_expression:   string;
  entry_actions:      string;
  exit_actions:       string;
  display_order:      number;
}

/** The "add a transition" row edits the same fields as an existing one. */
export type NewTransitionDraft = TransitionDraft;

interface ModelDraft {
  entity_logicalname: string;
  name:               string;
  state_field:        string;
  initial_state:      string;
  is_active:          boolean;
}

/** `"a, b ,,c"` -> `['a', 'b', 'c']`. */
export function splitActions(value: string): string[] {
  return value.split(',').map(s => s.trim()).filter(s => s.length > 0);
}

function emptyToNull(value: string): string | null {
  const v = value.trim();
  return v ? v : null;
}

function toDraft(t: StateTransition): TransitionDraft {
  return {
    from_state: t.from_state,
    to_state: t.to_state,
    name: t.name,
    required_privilege: t.required_privilege ?? '',
    guard_expression: t.guard_expression ?? '',
    entry_actions: t.entry_actions.join(', '),
    exit_actions: t.exit_actions.join(', '),
    display_order: t.display_order,
  };
}

function blankNewTransition(): NewTransitionDraft {
  return {
    from_state: '', to_state: '', name: '', required_privilege: '', guard_expression: '',
    entry_actions: '', exit_actions: '', display_order: 0,
  };
}

/** The `choices` array of a Choice attribute's `options`, or `[]`. */
function choicesOf(attr: AttributeMeta | undefined): string[] {
  const opts = attr?.options as { choices?: unknown } | null | undefined;
  return Array.isArray(opts?.choices) ? opts.choices.filter((c): c is string => typeof c === 'string') : [];
}

/**
 * U8 / M07 — the state-model admin screen over `/api/v1/admin/state-models*`.
 *
 * A model names an entity, one of its Choice fields (the states are that
 * field's options) and the initial state; its transitions are the allowed
 * `from -> to` edges, each optionally gated by a privilege. An edge can be
 * moved in place (its `from`/`to` are editable like any other field); the
 * server checks both are states of the model's field and that the pair is
 * not already used (409, shown as the server's message).
 *
 * Every update carries the `row_version` the screen last read; a stale one
 * is a 409 `version_conflict`, shown as a banner with a reload action,
 * never retried silently.
 */
@Component({
  selector: 'attome-state-models-manager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [OwnerLayerBadgeComponent, FormsModule, TranslatePipe, GovernanceNavComponent, StateDiagramComponent, ExpressionEditorComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css', './state-models-manager.component.css'],
  templateUrl: './state-models-manager.component.html',
})
export class StateModelsManagerComponent implements OnInit {
  private readonly svc = inject(StateModelsService);
  private readonly admin = inject(AdminService);
  private readonly confirmSvc = inject(ConfirmService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  /** Query param `?id=` — the model open on load. */
  readonly id = input<string | undefined>(undefined);

  readonly models = signal<StateModelListItem[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  readonly entities = signal<EntityMeta[]>([]);
  readonly choiceFields = signal<AttributeMeta[]>([]);
  readonly fieldsLoading = signal(false);

  readonly mode = signal<'none' | 'create' | 'edit'>('none');
  readonly draft = signal<ModelDraft>({
    entity_logicalname: '', name: '', state_field: '', initial_state: '', is_active: true,
  });
  readonly detail = signal<StateModelDetail | null>(null);
  readonly detailLoading = signal(false);

  readonly transitionDrafts = signal<Record<string, TransitionDraft>>({});
  readonly newTransition = signal<NewTransitionDraft>(blankNewTransition());

  readonly busy = signal(false);
  /** Set when a save hit a stale `row_version`. */
  readonly conflict = signal(false);
  /** The server's message for any other failed action. */
  readonly actionError = signal<string | null>(null);
  /** A translation key announced after a successful action. */
  readonly notice = signal<string | null>(null);

  /** The options of the currently chosen state field. */
  readonly stateOptions = computed(() =>
    choicesOf(this.choiceFields().find(f => f.logicalname === this.draft().state_field)));

  /** The state options for one transition row's `from`/`to` selects: the
   * field's options, plus `current` when an older edge still names a state
   * the field no longer offers (so the select never shows blank). */
  optionsFor(current: string): string[] {
    const options = this.stateOptions();
    return current && !options.includes(current) ? [current, ...options] : options;
  }

  /** Entities that have at least one Choice field are the only ones that
   * can carry a model, but that is only known per entity — list them all. */
  readonly sortedEntities = computed(() =>
    [...this.entities()].sort((a, b) => a.logicalname.localeCompare(b.logicalname)));

  ngOnInit(): void {
    this.loadModels();
    this.admin.listEntities().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: list => {
        this.entities.set(list);
        // An edit opened before the entity list arrived needs its fields now.
        const d = this.detail();
        if (d && this.choiceFields().length === 0) this.loadChoiceFields(d.entity_logicalname);
      },
      error: (e: ApiError) => this.actionError.set(e.message),
    });
    const initial = this.id();
    if (initial) this.open(initial);
  }

  loadModels(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listModels().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: items => { this.models.set(items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  // ── Create ────────────────────────────────────────────────────────────

  startCreate(): void {
    this.clearMessages();
    this.detail.set(null);
    this.choiceFields.set([]);
    this.draft.set({ entity_logicalname: '', name: '', state_field: '', initial_state: '', is_active: true });
    this.mode.set('create');
  }

  cancel(): void {
    this.clearMessages();
    this.mode.set('none');
    this.detail.set(null);
  }

  setDraft<K extends keyof ModelDraft>(key: K, value: ModelDraft[K]): void {
    this.draft.update(d => ({ ...d, [key]: value }));
  }

  chooseEntity(logicalname: string): void {
    this.draft.update(d => ({ ...d, entity_logicalname: logicalname, state_field: '', initial_state: '' }));
    this.loadChoiceFields(logicalname);
  }

  chooseStateField(field: string): void {
    this.draft.update(d => ({ ...d, state_field: field }));
    const options = this.stateOptions();
    if (!options.includes(this.draft().initial_state)) {
      this.draft.update(d => ({ ...d, initial_state: options[0] ?? '' }));
    }
  }

  canCreate(): boolean {
    const d = this.draft();
    return !!(d.entity_logicalname && d.name.trim() && d.state_field && d.initial_state) && !this.busy();
  }

  create(): void {
    if (!this.canCreate()) return;
    const d = this.draft();
    this.begin();
    this.svc.createModel({
      entity_logicalname: d.entity_logicalname,
      name: d.name.trim(),
      state_field: d.state_field,
      initial_state: d.initial_state,
      is_active: d.is_active,
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: created => {
        this.busy.set(false);
        this.notice.set('governance.stateModels.created');
        this.applyDetail(created);
        this.mode.set('edit');
        this.loadModels();
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  // ── Edit ──────────────────────────────────────────────────────────────

  open(id: string): void {
    this.clearMessages();
    this.mode.set('edit');
    this.detailLoading.set(true);
    this.svc.getModel(id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: d => {
        this.detailLoading.set(false);
        const entityChanged = this.detail()?.entity_logicalname !== d.entity_logicalname;
        this.applyDetail(d);
        if (entityChanged || this.choiceFields().length === 0) this.loadChoiceFields(d.entity_logicalname);
      },
      error: (e: ApiError) => { this.detailLoading.set(false); this.fail(e); },
    });
  }

  /** Re-reads the open model after a conflict, discarding local edits. */
  reload(): void {
    const d = this.detail();
    if (d) this.open(d.id);
  }

  saveModel(): void {
    const current = this.detail();
    const d = this.draft();
    if (!current || !d.name.trim() || !d.state_field || !d.initial_state) return;
    this.begin();
    this.svc.updateModel(current.id, {
      name: d.name.trim(),
      state_field: d.state_field,
      initial_state: d.initial_state,
      is_active: d.is_active,
      row_version: current.row_version,
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: updated => {
        this.busy.set(false);
        this.notice.set('governance.stateModels.saved');
        this.applyDetail(updated);
        this.loadModels();
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  async deleteModel(): Promise<void> {
    const current = this.detail();
    if (!current) return;
    const ok = await this.confirmSvc.confirm({
      title: this.lang.translate('governance.stateModels.deleteModelTitle'),
      message: this.lang.translate('governance.stateModels.deleteModelMessage', { name: current.name }),
      confirmText: this.lang.translate('governance.common.delete'),
      cancelText: this.lang.translate('governance.common.cancel'),
      variant: 'danger',
    });
    if (!ok) return;
    this.begin();
    this.svc.deleteModel(current.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set('governance.stateModels.deleted');
        this.detail.set(null);
        this.mode.set('none');
        this.loadModels();
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  // ── Transitions ───────────────────────────────────────────────────────

  setTransitionDraft<K extends keyof TransitionDraft>(id: string, key: K, value: TransitionDraft[K]): void {
    this.transitionDrafts.update(m => ({ ...m, [id]: { ...m[id], [key]: value } }));
  }

  setNewTransition<K extends keyof NewTransitionDraft>(key: K, value: NewTransitionDraft[K]): void {
    this.newTransition.update(t => ({ ...t, [key]: value }));
  }

  canAddTransition(): boolean {
    const t = this.newTransition();
    return !!(t.from_state && t.to_state && t.from_state !== t.to_state && t.name.trim()) && !this.busy();
  }

  addTransition(): void {
    const current = this.detail();
    if (!current || !this.canAddTransition()) return;
    const t = this.newTransition();
    this.begin();
    this.svc.createTransition(current.id, {
      from_state: t.from_state,
      to_state: t.to_state,
      name: t.name.trim(),
      required_privilege: emptyToNull(t.required_privilege),
      guard_expression: emptyToNull(t.guard_expression),
      entry_actions: splitActions(t.entry_actions),
      exit_actions: splitActions(t.exit_actions),
      display_order: Number(t.display_order) || 0,
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: created => {
        this.busy.set(false);
        this.notice.set('governance.stateModels.transitionAdded');
        this.replaceTransitions([...this.currentTransitions(), created]);
        this.newTransition.set(blankNewTransition());
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  saveTransition(t: StateTransition): void {
    const current = this.detail();
    const draft = this.transitionDrafts()[t.id];
    if (!current || !draft || !this.canSaveTransition(t)) return;
    this.begin();
    this.svc.updateTransition(current.id, t.id, {
      from_state: draft.from_state,
      to_state: draft.to_state,
      name: draft.name.trim(),
      required_privilege: emptyToNull(draft.required_privilege),
      guard_expression: emptyToNull(draft.guard_expression),
      entry_actions: splitActions(draft.entry_actions),
      exit_actions: splitActions(draft.exit_actions),
      display_order: Number(draft.display_order) || 0,
      row_version: t.row_version,
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: updated => {
        this.busy.set(false);
        this.notice.set('governance.stateModels.transitionSaved');
        this.replaceTransitions(this.currentTransitions().map(x => (x.id === updated.id ? updated : x)));
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  async deleteTransition(t: StateTransition): Promise<void> {
    const current = this.detail();
    if (!current) return;
    const ok = await this.confirmSvc.confirm({
      title: this.lang.translate('governance.stateModels.deleteTransitionTitle'),
      message: this.lang.translate('governance.stateModels.deleteTransitionMessage', {
        from: t.from_state, to: t.to_state,
      }),
      confirmText: this.lang.translate('governance.common.delete'),
      cancelText: this.lang.translate('governance.common.cancel'),
      variant: 'danger',
    });
    if (!ok) return;
    this.begin();
    this.svc.deleteTransition(current.id, t.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => {
        this.busy.set(false);
        this.notice.set('governance.stateModels.transitionDeleted');
        this.replaceTransitions(this.currentTransitions().filter(x => x.id !== t.id));
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  /** Dirty, named, a real edge (both ends set and different), not busy. */
  canSaveTransition(t: StateTransition): boolean {
    const draft = this.transitionDrafts()[t.id];
    return !!draft && this.isTransitionDirty(t) && !!draft.name.trim()
      && !!draft.from_state && !!draft.to_state && draft.from_state !== draft.to_state && !this.busy();
  }

  isTransitionDirty(t: StateTransition): boolean {
    const draft = this.transitionDrafts()[t.id];
    if (!draft) return false;
    const base = toDraft(t);
    return draft.from_state !== base.from_state
      || draft.to_state !== base.to_state
      || draft.name !== base.name
      || draft.required_privilege !== base.required_privilege
      || draft.guard_expression !== base.guard_expression
      || splitActions(draft.entry_actions).join(',') !== t.entry_actions.join(',')
      || splitActions(draft.exit_actions).join(',') !== t.exit_actions.join(',')
      || Number(draft.display_order) !== base.display_order;
  }

  // ── Internals ─────────────────────────────────────────────────────────

  private currentTransitions(): StateTransition[] {
    return this.detail()?.transitions ?? [];
  }

  private replaceTransitions(list: StateTransition[]): void {
    const current = this.detail();
    if (!current) return;
    const sorted = [...list].sort((a, b) => a.display_order - b.display_order || a.from_state.localeCompare(b.from_state));
    this.detail.set({ ...current, transitions: sorted });
    this.transitionDrafts.set(Object.fromEntries(sorted.map(t => [t.id, toDraft(t)])));
  }

  private applyDetail(d: StateModelDetail): void {
    this.detail.set(d);
    this.draft.set({
      entity_logicalname: d.entity_logicalname,
      name: d.name,
      state_field: d.state_field,
      initial_state: d.initial_state,
      is_active: d.is_active,
    });
    this.replaceTransitions(d.transitions);
    this.newTransition.set(blankNewTransition());
  }

  /** Loads the entity's Choice fields — the only ones a model can use. */
  private loadChoiceFields(logicalname: string): void {
    this.choiceFields.set([]);
    const entity = this.entities().find(e => e.logicalname === logicalname);
    if (!entity) return;
    this.fieldsLoading.set(true);
    this.admin.getEntity(entity.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: detail => {
        this.fieldsLoading.set(false);
        this.choiceFields.set(detail.attributes.filter(a => a.field_type === 'choice'));
      },
      error: (e: ApiError) => { this.fieldsLoading.set(false); this.actionError.set(e.message); },
    });
  }

  private begin(): void {
    this.busy.set(true);
    this.clearMessages();
  }

  private clearMessages(): void {
    this.conflict.set(false);
    this.actionError.set(null);
    this.notice.set(null);
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    if (e.kind === 'version_conflict') this.conflict.set(true);
    else this.actionError.set(e.message);
  }
}
