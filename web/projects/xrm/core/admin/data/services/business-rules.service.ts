import { inject, Injectable } from '@angular/core';
import { Observable, catchError, forkJoin, map, of, switchMap, tap } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents } from '@attome/base';
import type { ConditionTree, PolicyDef, RuleSeverity } from './business-rule.model';
import { EntityMetadataChangeService } from './entity-metadata-change.service';

/**
 * Business rules (D-789, as amended by D-790/D-791; design
 * `document/general/BUSINESS-RULES-DESIGN.md` sections 6 and 10) — the
 * `/api/v1/admin/business-rules` family: one-based list with filters, get
 * (with editor warnings), create, PATCH under `If-Match: "<row_version>"`,
 * retire, validate (no write), test (no write) and publish.
 *
 * The wire types are the generated `ApiComponents['schemas']` (from
 * `crates/engine/attome-api/src/rule_admin.rs` and `business_rule_admin.rs`),
 * narrowed only where the editor holds a closed set the generated document
 * types as a plain string, or the condition/policy types of `@attome/xrm`.
 */

/** `business`, or a kept legacy kind (Topic 15 #6). */
export type BusinessRuleKind = 'business' | 'visibility' | 'requirement' | 'policy' | 'routing';
/** Legacy kinds the editor still opens in the expression form. */
export const LEGACY_RULE_KINDS: readonly BusinessRuleKind[] = ['visibility', 'requirement', 'policy', 'routing'];

export type RuleAppliesTo = 'all' | 'roles';

type Schemas = ApiComponents['schemas'];

/**
 * `Local`, checked at compile time to stay assignable to the generated
 * `Generated`: the `@attome/xrm` condition and policy types are narrower than
 * the generated ones (no `null` for an omitted key, `skip_serializing_if`).
 */
type Narrows<Local extends Generated, Generated> = Local;

/** `RuleRoleRef`: one role a business rule applies to. */
export type RuleRoleRef = Schemas['RuleRoleRef'];

/**
 * An editor warning (design section 6.4); never blocks a write. `code` is
 * `required_field_locked`, `rule_applies_to_admins`, `no_matching_users`,
 * `set_value_conflict` or `locks_everyone`.
 */
export type RuleEditorWarning = Schemas['RuleEditorWarning'];

/** One validation problem, addressed by a path into the body (`condition.all[1].value`, `policies[0].field`). */
export type RuleIssue = Schemas['RuleIssue'];

/**
 * A rule as the admin API returns it. Narrowed: `kind` (generated as a string)
 * to `BusinessRuleKind`, `condition`/`policies` to the `@attome/xrm` types the
 * editor and the client evaluator use. `condition` is required: the Rust
 * `Option` is always serialized (`null` when unset).
 */
export type BusinessRule = Omit<Schemas['BusinessRule'], 'kind' | 'condition' | 'policies'> & {
  kind: BusinessRuleKind;
  condition: Narrows<ConditionTree, Schemas['ConditionTree']> | null;
  policies: Narrows<PolicyDef, Schemas['PolicyDef']>[];
};

/**
 * `POST /api/v1/admin/business-rules` and `/validate`. Narrowed: `kind` and
 * `severity` (generated as strings) to the editor's closed sets.
 */
export type BusinessRuleBody = Omit<Schemas['BusinessRuleBody'], 'kind' | 'severity'> & {
  kind?: BusinessRuleKind;
  severity?: RuleSeverity;
};

/** `PATCH /api/v1/admin/business-rules/{id}`: any body field; `entity`/`name` may be sent but not changed. */
export type BusinessRulePatch = Omit<Schemas['BusinessRulePatch'], 'kind' | 'severity'> & {
  kind?: BusinessRuleKind;
  severity?: RuleSeverity;
};

/** `POST …/validate` (`ValidateResponse`): nothing is written. */
export type RuleValidateResponse = Schemas['ValidateResponse'];

/** Who a rule is tested for (`TestAudience`). Absent: evaluated as if it applied. */
export type RuleTestAudience = Schemas['TestAudience'];

export type RuleTestRequest = Schemas['RuleTestRequest'];

/** `POST …/{id}/test`. Narrowed: `condition` (generated as a string) to its four values. */
export type RuleTestResponse = Omit<Schemas['RuleTestResponse'], 'condition'> & {
  condition: 'true' | 'false' | 'unknown' | 'transient';
};

export interface BusinessRuleFilter {
  entity?: string;
  kind?: BusinessRuleKind;
  role_id?: string;
  portal_role_id?: string;
  is_active?: boolean;
}

/** A role an audience can name: a staff role, or a portal role with its portal. */
export interface AudienceRoleOption {
  id: string;
  name: string;
  /** `null` for a staff role; the portal's display name for a portal role. */
  portal: string | null;
}

interface PageOf<T> { items: T[]; total: number; page: number; page_size: number }
interface StaffRoleWire { id: string; name: string }
interface PortalWire { id: string; name: string }
interface PortalRoleWire { id: string; name: string }

@Injectable({ providedIn: 'root' })
export class BusinessRulesService {
  private readonly api = inject(ApiService);
  private readonly metadataChanged = inject(EntityMetadataChangeService);

  /** Every rule matching `filter` (one-based list, D-731). */
  list(filter: BusinessRuleFilter = {}): Observable<BusinessRule[]> {
    const params: Record<string, string> = {};
    if (filter.entity) params['entity'] = filter.entity;
    if (filter.kind) params['kind'] = filter.kind;
    if (filter.role_id) params['role_id'] = filter.role_id;
    if (filter.portal_role_id) params['portal_role_id'] = filter.portal_role_id;
    if (filter.is_active !== undefined) params['is_active'] = String(filter.is_active);
    return this.api.getAllPages<BusinessRule>('/api/v1/admin/business-rules', params, 200, undefined, 1);
  }

  /** One rule with its editor warnings. */
  get(id: string): Observable<BusinessRule> {
    return this.api.get<BusinessRule>(`/api/v1/admin/business-rules/${id}`);
  }

  /** 201 with warnings; a repeat of an identical create answers 200 with the existing rule. */
  create(body: BusinessRuleBody): Observable<BusinessRule> {
    return this.api.post<BusinessRule>('/api/v1/admin/business-rules', body)
      .pipe(this.notifyOnSuccess());
  }

  /** `rowVersion` is sent as `If-Match` (required: 422 without it, 409 `version_conflict` when stale). */
  update(id: string, patch: BusinessRulePatch, rowVersion: number): Observable<BusinessRule> {
    return this.api.patch<BusinessRule>(`/api/v1/admin/business-rules/${id}`, patch, rowVersion)
      .pipe(this.notifyOnSuccess());
  }

  /** Retires the rule (`is_active = false`). */
  retire(id: string): Observable<void> {
    return this.api.delete(`/api/v1/admin/business-rules/${id}`).pipe(this.notifyOnSuccess());
  }

  /** Validates a body against the live schema, roles and limits; writes nothing. */
  validate(body: BusinessRuleBody): Observable<RuleValidateResponse> {
    return this.api.post<RuleValidateResponse>('/api/v1/admin/business-rules/validate', body);
  }

  /** Evaluates the SAVED rule against a sample record for an audience; writes nothing. */
  test(id: string, request: RuleTestRequest): Observable<RuleTestResponse> {
    return this.api.post<RuleTestResponse>(`/api/v1/admin/business-rules/${id}/test`, request);
  }

  /** Snapshots the rule into its version history and bumps `version`. */
  publish(id: string): Observable<BusinessRule> {
    return this.api.post<BusinessRule>(`/api/v1/admin/business-rules/${id}/publish`, {})
      .pipe(this.notifyOnSuccess());
  }

  /** Staff roles (`/api/v1/admin/security/roles`). */
  staffRoles(): Observable<AudienceRoleOption[]> {
    return this.api.getAllPages<StaffRoleWire>('/api/v1/admin/security/roles').pipe(
      map(items => items.map(r => ({ id: r.id, name: r.name, portal: null }))),
    );
  }

  /**
   * Web-portal roles of every portal, grouped by portal in the picker. The
   * portal module may not be installed or licensed: a failed lookup yields
   * no portal roles rather than failing the editor.
   */
  portalRoles(): Observable<AudienceRoleOption[]> {
    return this.api.get<PageOf<PortalWire>>('/api/v1/admin/webportals', { page: '1', page_size: '200' }).pipe(
      switchMap(page => page.items.length === 0
        ? of([] as AudienceRoleOption[][])
        : forkJoin(page.items.map(portal =>
          this.api.get<PageOf<PortalRoleWire>>(`/api/v1/admin/webportals/${portal.id}/roles`).pipe(
            map(roles => roles.items.map(r => ({ id: r.id, name: r.name, portal: portal.name }))),
            catchError(() => of([] as AudienceRoleOption[])),
          )))),
      map(groups => groups.flat()),
      catchError(() => of([] as AudienceRoleOption[])),
    );
  }

  /**
   * A rule write changes what `/schema` delivers, so the record form's
   * schema cache in this tab is dropped (the TTL covers other tabs).
   */
  private notifyOnSuccess<T>(): (source: Observable<T>) => Observable<T> {
    return source => source.pipe(tap(() => this.metadataChanged.notify()));
  }
}
