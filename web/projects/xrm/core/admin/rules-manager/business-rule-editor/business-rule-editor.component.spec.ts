import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, LangService } from '@attome/base';
import { AdminService, BusinessRule, BusinessRulesService, EntityMeta } from '@attome/xrm/core/admin/data';
import {
  BusinessRuleEditorComponent, cleanPolicy, issuePathsFromMessage,
} from './business-rule-editor.component';

const ENTITIES = [{ id: 'e1', logicalname: 'deal', name: 'Deal' }] as unknown as EntityMeta[];

const ATTRIBUTES = [
  { logicalname: 'status', name: 'Status', field_type: 'choice', options: { choices: ['open', 'closed'] }, is_active: true, is_sensitive: false },
  { logicalname: 'amount', name: 'Amount', field_type: 'number', options: null, is_active: true, is_sensitive: false },
];

function rule(over: Partial<BusinessRule> = {}): BusinessRule {
  return {
    id: 'r1', entity_logicalname: 'deal', name: 'closed_lock', kind: 'business',
    display_name: 'Closed deals', description: null, applies_to: 'all', roles: [],
    condition: { field: 'status', op: 'eq', value: 'closed' },
    policies: [{ type: 'disabled', field: 'amount' }],
    target_field: null, expression: null, message: null, severity: 'error',
    is_active: true, display_order: 0, version: 1, row_version: 4, owner_layer: 'customer',
    disabled_reason: null, applies_to_nobody: false, load_error: null,
    warnings: [{ code: 'rule_applies_to_admins', message: 'admins too' }],
    ...over,
  };
}

describe('BusinessRuleEditorComponent (D-789 section 10)', () => {
  let service: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    service = {
      create: vi.fn(),
      update: vi.fn().mockReturnValue(of(rule({ row_version: 5, warnings: [] }))),
      validate: vi.fn().mockReturnValue(of({ valid: false, issues: [{ path: 'condition.value', code: 'value_type', message: 'bad' }], warnings: [] })),
      publish: vi.fn(),
      retire: vi.fn(),
      get: vi.fn(),
      test: vi.fn(),
    };
    TestBed.configureTestingModule({
      imports: [BusinessRuleEditorComponent],
      providers: [
        { provide: BusinessRulesService, useValue: service },
        // Z11-T14: the expression editor loads the entity's fields and the function list.
        { provide: ApiService, useValue: { get: () => of({}), post: vi.fn() } },
        { provide: AdminService, useValue: { getEntity: vi.fn().mockReturnValue(of({ attributes: ATTRIBUTES })) } },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: () => 'error' } },
      ],
    });
  });

  function render(r: BusinessRule | null) {
    const fixture = TestBed.createComponent(BusinessRuleEditorComponent);
    fixture.componentRef.setInput('rule', r);
    fixture.componentRef.setInput('entities', ENTITIES);
    fixture.detectChanges();
    return { fixture, c: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  it('loads a rule, wraps a single leaf in a group, and shows its warnings', () => {
    const { c, el } = render(rule());
    expect(c.draft().condition).toEqual({ all: [{ field: 'status', op: 'eq', value: 'closed' }] });
    expect(el.querySelector('[data-testid="rule-warnings"]')?.textContent)
      .toContain('businessRules.warning.rule_applies_to_admins');
  });

  it('refuses a lock policy together with an advanced expression', () => {
    const { c, fixture, el } = render(rule());
    c.setCondition({ all: [{ expression: 'amount > 1' }] });
    fixture.detectChanges();
    expect(c.localIssues()).toContain('businessRules.issue.lockWithAdvanced');
    expect(c.canSave()).toBe(false);
    expect(el.querySelector('[data-testid="rule-local-issues"]')).not.toBeNull();
  });

  it('saves with If-Match (the loaded row_version)', () => {
    const { c } = render(rule());
    c.patch({ display_name: 'Closed' });
    c.save();
    expect(service['update']).toHaveBeenCalledWith('r1', expect.objectContaining({
      kind: 'business', display_name: 'Closed', applies_to: 'all',
      policies: [{ type: 'disabled', field: 'amount' }],
    }), 4);
  });

  it('shows the conflict banner on a stale row_version', () => {
    service['update'].mockReturnValue(throwError(() => ({ kind: 'version_conflict', status: 409, message: '' })));
    const { c, fixture, el } = render(rule());
    c.save();
    fixture.detectChanges();
    expect(c.conflict()).toBe(true);
    expect(el.querySelector('[data-testid="rule-conflict"]')).not.toBeNull();
  });

  it('shows validation issues from /validate', () => {
    const { c, fixture, el } = render(rule());
    c.validate();
    fixture.detectChanges();
    expect(el.querySelector('[data-testid="rule-issues"]')?.textContent).toContain('condition.value');
  });

  it('a roles audience needs a role', () => {
    const { c } = render(null);
    c.patch({ applies_to: 'roles' });
    expect(c.localIssues()).toContain('businessRules.issue.noRoles');
  });

  it('opens a legacy kind in the expression form', () => {
    const { c } = render(rule({ kind: 'routing', condition: null, policies: [], expression: 'priority == "high"' }));
    expect(c.isLegacy()).toBe(true);
    expect(c.legacy()?.expression).toBe('priority == "high"');
  });
});

describe('cleanPolicy / issuePathsFromMessage', () => {
  it('keeps only the members a policy type uses', () => {
    expect(cleanPolicy({ type: 'hidden', field: 'a', message: 'x' })).toEqual({ type: 'hidden', field: 'a' });
    expect(cleanPolicy({ type: 'set_value', field: 'a', value: 1, expression: 'b' }))
      .toEqual({ type: 'set_value', field: 'a', mode: 'always', expression: 'b' });
    expect(cleanPolicy({ type: 'error', message: ' m ' })).toEqual({ type: 'error', message: 'm', severity: 'error' });
  });

  it('reads issue paths out of a 422 message', () => {
    expect(issuePathsFromMessage('condition.all[0].op: nope; policies[1].field: missing; If-Match: x'))
      .toEqual(['condition.all[0].op', 'policies[1].field']);
  });
});
