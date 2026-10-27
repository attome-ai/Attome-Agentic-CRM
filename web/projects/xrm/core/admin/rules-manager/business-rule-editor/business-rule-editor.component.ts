import {
  ChangeDetectionStrategy, Component, computed, DestroyRef, effect, inject, input, output, signal, untracked,
} from '@angular/core';
import { ExpressionEditorComponent } from '@attome/xrm/core/admin/expression-editor';
import { KeyValuePipe } from '@angular/common';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  AdminService, AttributeMeta, AudienceRoleOption, BusinessRule, BusinessRuleBody, BusinessRulePatch,
  BusinessRulesService, ConditionTree, CONDITION_SYSTEM_FIELDS, PolicyDef, PolicyType, RuleAppliesTo,
  RuleEditorWarning, RuleIssue, RuleSeverity, RuleTestRequest, RuleTestResponse, EntityMeta,
  conditionFieldKind, conditionHasExpression, isConditionAll, isConditionAny,
} from '@attome/xrm/core/admin/data';
import {
  ConditionEditorField, ConditionGroup, ConditionGroupComponent, scalarFromInput,
} from '../condition-group/condition-group.component';

/** The editable state of one business rule (design section 10). */
export interface BusinessRuleDraft {
  entity: string;
  name: string;
  display_name: string;
  description: string;
  applies_to: RuleAppliesTo;
  role_ids: string[];
  portal_role_ids: string[];
  /** Always a group in the editor; a stored leaf is wrapped in `{all: [leaf]}`. */
  condition: ConditionGroup;
  policies: PolicyDef[];
  is_active: boolean;
  display_order: number;
}

/** A kept legacy kind's expression form (`visibility`, `requirement`, `policy`, `routing`). */
export interface LegacyRuleDraft {
  target_field: string;
  expression: string;
  message: string;
  severity: RuleSeverity;
  is_active: boolean;
  display_order: number;
}

/** Who the test panel evaluates the saved rule for. */
export type TestAudienceMode = 'unscoped' | 'staff' | 'portal' | 'integration' | 'system';

export const POLICY_TYPES: readonly PolicyType[] = ['hidden', 'disabled', 'error', 'set_value'];

/** Editor-warning codes with a translated text (design section 6.4). */
const KNOWN_WARNING_CODES = new Set([
  'required_field_locked', 'rule_applies_to_admins', 'no_matching_users', 'set_value_conflict', 'locks_everyone',
]);

/** `"path: message; path: message"` (`rule_admin::issues_error`) → the issue paths. */
export function issuePathsFromMessage(message: string): string[] {
  return message.split('; ')
    .map(part => part.split(': ', 1)[0]?.trim() ?? '')
    .filter(p => /^(condition|policies|entity|name|display_name|applies_to|role_ids|portal_role_ids)\b/.test(p));
}

function emptyDraft(entity = ''): BusinessRuleDraft {
  return {
    entity, name: '', display_name: '', description: '',
    applies_to: 'all', role_ids: [], portal_role_ids: [],
    condition: { all: [] }, policies: [], is_active: true, display_order: 0,
  };
}

function rootGroup(c: ConditionTree | null): ConditionGroup {
  if (!c) return { all: [] };
  if (isConditionAll(c) || isConditionAny(c)) return c;
  return { all: [c] };
}

/** A policy as the API takes it: only the members its type uses. */
export function cleanPolicy(p: PolicyDef): PolicyDef {
  switch (p.type) {
    case 'hidden':
    case 'disabled':
      return { type: p.type, field: p.field ?? '' };
    case 'error': {
      const out: PolicyDef = { type: 'error', message: (p.message ?? '').trim(), severity: p.severity ?? 'error' };
      if (p.field) out.field = p.field;
      return out;
    }
    case 'set_value': {
      const out: PolicyDef = { type: 'set_value', field: p.field ?? '', mode: p.mode ?? 'always' };
      if (p.expression !== undefined) out.expression = p.expression;
      else if (p.value !== undefined) out.value = p.value;
      return out;
    }
    // A11-T1: required while the condition holds.
    case 'required': {
      const out: PolicyDef = { type: 'required', field: p.field ?? '' };
      if (p.message?.trim()) out.message = p.message.trim();
      return out;
    }
    // A11-T1: only the listed codes while the condition holds.
    case 'allowed_values': {
      const out: PolicyDef = { type: 'allowed_values', field: p.field ?? '', value: p.value ?? [] };
      if (p.message?.trim()) out.message = p.message.trim();
      return out;
    }
    // B4-T3: tag or untag the record.
    case 'add_tag':
    case 'remove_tag':
      return { type: p.type, value: typeof p.value === 'string' ? p.value.trim() : '' };
  }
}

/**
 * D-789 section 10 — the business-rule editor: name, display name and
 * description; **applies to** all users or roles (staff roles, portal roles
 * grouped by portal); the AND/OR **condition** builder; ordered **policies**
 * (hide field, lock field, show error, set value); the editor **warnings**
 * (section 6.4, never blocking) and validation issues; **validate**, **test**
 * (a sample record for an audience; the saved rule) and **publish**. Saves
 * PATCH under `If-Match: "<row_version>"`; a 409 offers a reload. Legacy
 * kinds open in the expression form, marked legacy; a converted rule says
 * what it was converted from.
 */
@Component({
  selector: 'xrm-business-rule-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [KeyValuePipe, TranslatePipe, ConditionGroupComponent, ExpressionEditorComponent],
  styleUrls: ['./business-rule-editor.component.css'],
  templateUrl: './business-rule-editor.component.html',
})
export class BusinessRuleEditorComponent {
  /** The rule being edited; `null` for a new business rule. */
  readonly rule = input<BusinessRule | null>(null);
  readonly entities = input.required<readonly EntityMeta[]>();
  readonly staffRoles = input<readonly AudienceRoleOption[]>([]);
  readonly portalRoles = input<readonly AudienceRoleOption[]>([]);
  /** Pre-selects the entity of a new rule (the list's entity filter). */
  readonly defaultEntity = input('');

  readonly saved = output<BusinessRule>();
  readonly retired = output<string>();
  readonly closed = output<void>();

  private readonly service = inject(BusinessRulesService);
  private readonly admin = inject(AdminService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly policyTypes = POLICY_TYPES;

  readonly draft = signal<BusinessRuleDraft>(emptyDraft());
  readonly legacy = signal<LegacyRuleDraft | null>(null);
  readonly attributes = signal<readonly AttributeMeta[]>([]);
  readonly attributesError = signal(false);

  readonly issues = signal<readonly RuleIssue[]>([]);
  readonly warnings = signal<readonly RuleEditorWarning[]>([]);
  readonly validated = signal<boolean | null>(null);
  readonly error = signal('');
  readonly notice = signal('');
  readonly conflict = signal(false);
  readonly saving = signal(false);
  readonly validating = signal(false);
  readonly publishing = signal(false);
  readonly retiring = signal(false);

  readonly testRecord = signal('{}');
  readonly testMode = signal<TestAudienceMode>('unscoped');
  readonly testRoleIds = signal<readonly string[]>([]);
  readonly testPortalRoleId = signal<string>('');
  readonly testing = signal(false);
  readonly testResult = signal<RuleTestResponse | null>(null);
  readonly testError = signal('');

  readonly isNew = computed(() => this.rule() === null);
  readonly isLegacy = computed(() => this.legacy() !== null);

  protected readonly entityName = computed(() => this.draft().entity);
  /** The id of the rule the draft was last loaded from. */
  private shownRuleId: string | null = null;

  /** Fields a condition may read: the entity's eligible attributes plus owner and organization. */
  readonly conditionFields = computed<readonly ConditionEditorField[]>(() => {
    const out: ConditionEditorField[] = [];
    for (const a of this.attributes()) {
      if (!a.is_active) continue;
      const kind = conditionFieldKind(a);
      if (!kind) continue;
      const opts = (a.options ?? null) as { choices?: string[]; option_labels?: Record<string, string> | null } | null;
      out.push({
        name: a.logicalname,
        label: a.is_sensitive
          ? this.lang.translate('businessRules.field.sensitive', { name: a.name || a.logicalname })
          : (a.name || a.logicalname),
        kind,
        choices: Array.isArray(opts?.choices) ? opts.choices : [],
        choiceLabels: opts?.option_labels ?? null,
      });
    }
    for (const name of CONDITION_SYSTEM_FIELDS) {
      out.push({ name, label: this.lang.translate(`businessRules.field.${name}`), kind: 'lookup', choices: [] });
    }
    return out;
  });

  /** Fields a policy may target (every active attribute; `set_value` never a formula). */
  readonly policyFields = computed(() =>
    this.attributes().filter(a => a.is_active).map(a => ({
      name: a.logicalname, label: a.name || a.logicalname, formula: a.field_type === 'formula',
    })));

  /** Portal roles grouped by portal for the audience picker. */
  readonly portalGroups = computed(() => {
    const groups = new Map<string, AudienceRoleOption[]>();
    for (const r of this.portalRoles()) {
      const key = r.portal ?? '';
      groups.set(key, [...(groups.get(key) ?? []), r]);
    }
    return [...groups.entries()].map(([portal, roles]) => ({ portal, roles }));
  });

  /** Problems the editor sees before asking the server (design sections 2 and 6.2). */
  readonly localIssues = computed<readonly string[]>(() => {
    if (this.isLegacy()) return [];
    const d = this.draft();
    const out: string[] = [];
    const hasLock = d.policies.some(p => p.type === 'hidden' || p.type === 'disabled');
    if (hasLock && conditionHasExpression(d.condition)) out.push('businessRules.issue.lockWithAdvanced');
    if (d.applies_to === 'roles' && d.role_ids.length + d.portal_role_ids.length === 0) {
      out.push('businessRules.issue.noRoles');
    }
    if (d.policies.length === 0) out.push('businessRules.issue.noPolicies');
    return out;
  });

  readonly issuePaths = computed(() => this.issues().map(i => i.path));

  readonly canSave = computed(() => {
    if (this.saving()) return false;
    if (this.isLegacy()) return (this.legacy()?.expression.trim() ?? '') !== '';
    const d = this.draft();
    return d.entity.trim() !== '' && d.name.trim() !== '' && this.localIssues().length === 0;
  });

  constructor() {
    effect(() => {
      const r = this.rule();
      untracked(() => this.reset(r));
    });
    // Load the attributes of the rule's entity (once per entity, not per edit).
    effect(() => {
      const name = this.entityName();
      const entity = this.entities().find(e => e.logicalname === name);
      untracked(() => this.loadAttributes(entity?.id ?? null));
    });
  }

  // ── Loading ───────────────────────────────────────────────────────────────
  /**
   * Loads `r` into the draft. A refresh of the same rule (after its own
   * save, publish or reload) keeps the notice and the test panel; another
   * rule starts clean.
   */
  private reset(r: BusinessRule | null): void {
    const sameRule = r !== null && r.id === this.shownRuleId;
    this.shownRuleId = r?.id ?? null;
    this.issues.set([]);
    this.validated.set(null);
    this.error.set('');
    this.conflict.set(false);
    if (!sameRule) {
      this.notice.set('');
      this.testResult.set(null);
      this.testError.set('');
    }
    this.warnings.set(r?.warnings ?? []);
    if (!r) {
      this.legacy.set(null);
      this.draft.set(emptyDraft(this.defaultEntity()));
      return;
    }
    this.draft.set({
      entity: r.entity_logicalname,
      name: r.name,
      display_name: r.display_name ?? '',
      description: r.description ?? '',
      applies_to: r.applies_to,
      role_ids: r.roles.filter(x => !x.portal_role && x.live).map(x => x.id),
      portal_role_ids: r.roles.filter(x => x.portal_role).map(x => x.id),
      condition: rootGroup(r.condition),
      policies: r.policies.map(p => ({ ...p })),
      is_active: r.is_active,
      display_order: r.display_order,
    });
    this.legacy.set(r.kind === 'business' ? null : {
      target_field: r.target_field ?? '',
      expression: r.expression ?? '',
      message: r.message ?? '',
      severity: r.severity === 'warning' ? 'warning' : 'error',
      is_active: r.is_active,
      display_order: r.display_order,
    });
  }

  private loadAttributes(entityId: string | null): void {
    this.attributesError.set(false);
    if (!entityId) {
      this.attributes.set([]);
      return;
    }
    this.admin.getEntity(entityId).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: detail => {
        if (this.entities().find(e => e.id === entityId)?.logicalname === this.entityName()) {
          this.attributes.set(detail.attributes);
        }
      },
      error: () => { this.attributes.set([]); this.attributesError.set(true); },
    });
  }

  // ── Draft edits ───────────────────────────────────────────────────────────
  patch(p: Partial<BusinessRuleDraft>): void {
    this.draft.update(d => ({ ...d, ...p }));
    this.validated.set(null);
  }

  patchLegacy(p: Partial<LegacyRuleDraft>): void {
    this.legacy.update(d => d ? { ...d, ...p } : d);
  }

  /** A new rule's entity: its condition and policies start over (they name that entity's fields). */
  setEntity(entity: string): void {
    this.patch({ entity, condition: { all: [] }, policies: [] });
  }

  setCondition(group: ConditionGroup): void {
    this.patch({ condition: group });
  }

  toggleRole(id: string, portal: boolean): void {
    const toggle = (held: string[]) => held.includes(id) ? held.filter(x => x !== id) : [...held, id];
    if (portal) this.patch({ portal_role_ids: toggle(this.draft().portal_role_ids) });
    else this.patch({ role_ids: toggle(this.draft().role_ids) });
  }

  hasRole(id: string, portal: boolean): boolean {
    return (portal ? this.draft().portal_role_ids : this.draft().role_ids).includes(id);
  }

  addPolicy(type: PolicyType): void {
    const first = this.policyFields().find(f => type !== 'set_value' || !f.formula)?.name;
    const p: PolicyDef = type === 'error'
      ? { type, message: '', severity: 'error' }
      : type === 'set_value'
        ? { type, field: first ?? '', mode: 'always' }
        : { type, field: first ?? '' };
    this.patch({ policies: [...this.draft().policies, p] });
  }

  updatePolicy(i: number, p: Partial<PolicyDef>): void {
    this.patch({ policies: this.draft().policies.map((x, j) => j === i ? { ...x, ...p } : x) });
  }

  setPolicyType(i: number, type: PolicyType): void {
    const old = this.draft().policies[i];
    const next: PolicyDef = { type, field: old?.field };
    if (type === 'error') { next.message = old?.message ?? ''; next.severity = old?.severity ?? 'error'; }
    if (type === 'set_value') next.mode = 'always';
    this.patch({ policies: this.draft().policies.map((x, j) => j === i ? next : x) });
  }

  /** `literal` or `expression` for a `set_value` policy. */
  setValueSource(i: number, source: 'literal' | 'expression'): void {
    const p = this.draft().policies[i];
    if (!p) return;
    const next: PolicyDef = { type: p.type, field: p.field, mode: p.mode ?? 'always' };
    if (source === 'expression') next.expression = '';
    this.patch({ policies: this.draft().policies.map((x, j) => j === i ? next : x) });
  }

  setPolicyValue(i: number, raw: string): void {
    const p = this.draft().policies[i];
    if (!p) return;
    const attr = this.attributes().find(a => a.logicalname === p.field);
    const kind = attr ? conditionFieldKind(attr) : undefined;
    const next: PolicyDef = { type: p.type, field: p.field, mode: p.mode };
    const value = kind ? scalarFromInput(kind, raw) : (raw.trim() || undefined);
    if (value !== undefined) next.value = value;
    this.patch({ policies: this.draft().policies.map((x, j) => j === i ? next : x) });
  }

  policyValueText(p: PolicyDef): string {
    return p.value === undefined || p.value === null ? '' : String(p.value);
  }

  movePolicy(i: number, delta: -1 | 1): void {
    const list = [...this.draft().policies];
    const j = i + delta;
    if (j < 0 || j >= list.length) return;
    [list[i], list[j]] = [list[j], list[i]];
    this.patch({ policies: list });
  }

  removePolicy(i: number): void {
    this.patch({ policies: this.draft().policies.filter((_, j) => j !== i) });
  }

  policyHasIssue(i: number): boolean {
    return this.issuePaths().some(p => p === `policies[${i}]` || p.startsWith(`policies[${i}].`));
  }

  fieldLabel(name: string | undefined | null): string {
    if (!name) return '';
    return this.attributes().find(a => a.logicalname === name)?.name || name;
  }

  warningText(w: RuleEditorWarning): string {
    return KNOWN_WARNING_CODES.has(w.code)
      ? this.lang.translate(`businessRules.warning.${w.code}`, { field: this.fieldLabel(w.field) })
      : w.message;
  }

  // ── Body ──────────────────────────────────────────────────────────────────
  toBody(): BusinessRuleBody {
    const d = this.draft();
    const roles = d.applies_to === 'roles';
    return {
      entity: d.entity.trim(),
      name: d.name.trim(),
      kind: 'business',
      // An empty string clears on PATCH (a `null` would keep the stored value).
      display_name: d.display_name.trim(),
      description: d.description.trim(),
      applies_to: d.applies_to,
      role_ids: roles ? d.role_ids : [],
      portal_role_ids: roles ? d.portal_role_ids : [],
      condition: d.condition,
      policies: d.policies.map(cleanPolicy),
      is_active: d.is_active,
      display_order: d.display_order,
    };
  }

  private legacyPatch(): BusinessRulePatch {
    const l = this.legacy();
    if (!l) return {};
    return {
      target_field: l.target_field.trim() || null,
      expression: l.expression,
      message: l.message.trim() || null,
      severity: l.severity,
      is_active: l.is_active,
      display_order: l.display_order,
    };
  }

  // ── Actions ───────────────────────────────────────────────────────────────
  save(): void {
    if (!this.canSave()) return;
    const current = this.rule();
    this.saving.set(true);
    this.error.set('');
    this.notice.set('');
    this.issues.set([]);
    const request$ = current === null
      ? this.service.create(this.toBody())
      : this.service.update(current.id, this.isLegacy() ? this.legacyPatch() : this.toBody(), current.row_version);
    request$.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: rule => {
        this.saving.set(false);
        // The host feeds the saved rule back through `rule`; treat it as a
        // refresh of this rule (a create included), keeping the notice.
        this.shownRuleId = rule.id;
        this.saved.emit(rule);
        this.warnings.set(rule.warnings ?? []);
        this.notice.set('businessRules.notice.saved');
      },
      error: (e: ApiError) => {
        this.saving.set(false);
        this.fail(e);
      },
    });
  }

  validate(): void {
    if (this.isLegacy()) return;
    this.validating.set(true);
    this.error.set('');
    this.service.validate(this.toBody()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.validating.set(false);
        this.issues.set(res.issues);
        this.warnings.set(res.warnings);
        this.validated.set(res.valid);
      },
      error: (e: ApiError) => { this.validating.set(false); this.fail(e); },
    });
  }

  publish(): void {
    const current = this.rule();
    if (!current) return;
    this.publishing.set(true);
    this.error.set('');
    this.notice.set('');
    this.service.publish(current.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: rule => {
        this.publishing.set(false);
        this.saved.emit(rule);
        this.notice.set('businessRules.notice.published');
      },
      error: (e: ApiError) => { this.publishing.set(false); this.fail(e); },
    });
  }

  retire(): void {
    const current = this.rule();
    if (!current) return;
    this.retiring.set(true);
    this.error.set('');
    this.service.retire(current.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: () => { this.retiring.set(false); this.retired.emit(current.id); },
      error: (e: ApiError) => { this.retiring.set(false); this.fail(e); },
    });
  }

  /** Resolves a 409: re-reads the rule (its warnings included) and drops the local edits. */
  reload(): void {
    const current = this.rule();
    if (!current) return;
    this.service.get(current.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: rule => { this.conflict.set(false); this.saved.emit(rule); },
      error: (e: ApiError) => this.fail(e),
    });
  }

  runTest(): void {
    const current = this.rule();
    if (!current) return;
    let record: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(this.testRecord() || '{}');
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new Error('not an object');
      record = parsed as Record<string, unknown>;
    } catch {
      this.testError.set(this.lang.translate('businessRules.test.badJson'));
      return;
    }
    const request: RuleTestRequest = { record };
    switch (this.testMode()) {
      case 'staff':       request.as = { role_ids: [...this.testRoleIds()] }; break;
      case 'portal':      request.as = { portal_role_id: this.testPortalRoleId() || null }; break;
      case 'integration': request.as = { role_ids: [...this.testRoleIds()], interactive: false }; break;
      case 'system':      request.as = { system: true }; break;
      case 'unscoped':    break;
    }
    this.testing.set(true);
    this.testError.set('');
    this.testResult.set(null);
    this.service.test(current.id, request).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => { this.testing.set(false); this.testResult.set(res); },
      error: (e: ApiError) => { this.testing.set(false); this.testError.set(e.message || this.lang.errorText(e)); },
    });
  }

  toggleTestRole(id: string): void {
    const held = this.testRoleIds();
    this.testRoleIds.set(held.includes(id) ? held.filter(x => x !== id) : [...held, id]);
  }

  /** "Hide Amount", "Show error", … for a policy the test fired. */
  firedPolicyText(ordinal: number): string {
    const p = this.rule()?.policies[ordinal];
    if (!p) return `#${ordinal + 1}`;
    return this.lang.translate(`businessRules.policy.summary.${p.type}`, { field: this.fieldLabel(p.field) });
  }

  testValueText(v: unknown): string {
    return typeof v === 'string' ? v : JSON.stringify(v);
  }

  close(): void { this.closed.emit(); }

  private fail(e: ApiError): void {
    if (e.kind === 'version_conflict') {
      this.conflict.set(true);
      return;
    }
    this.error.set(e.message || this.lang.errorText(e));
    if (e.kind === 'validation' && e.message) {
      this.issues.set(issuePathsFromMessage(e.message).map(path => ({ path, code: 'invalid', message: '' })));
    }
  }
}
