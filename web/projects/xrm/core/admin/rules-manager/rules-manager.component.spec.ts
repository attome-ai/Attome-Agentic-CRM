import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import {
  AdminService, BusinessRule, BusinessRulesService, ChangesetContextService,
} from '@attome/xrm/core/admin/data';
import { RulesManagerComponent, summarizePolicies } from './rules-manager.component';

function rule(over: Partial<BusinessRule>): BusinessRule {
  return {
    id: 'r1', entity_logicalname: 'deal', name: 'n', kind: 'business', display_name: null,
    description: null, applies_to: 'all', roles: [], condition: { all: [] }, policies: [],
    target_field: null, expression: null, message: null, severity: 'error', is_active: true,
    display_order: 0, version: 0, row_version: 1, owner_layer: 'customer', disabled_reason: null,
    applies_to_nobody: false, load_error: null, warnings: [],
    ...over,
  };
}

describe('summarizePolicies', () => {
  it('counts each policy type', () => {
    expect(summarizePolicies(rule({
      policies: [
        { type: 'hidden', field: 'a' }, { type: 'hidden', field: 'b' }, { type: 'disabled', field: 'c' },
        { type: 'error', message: 'm', severity: 'error' }, { type: 'set_value', field: 'd', value: 1, mode: 'always' },
      ],
    }))).toEqual({ hides: 2, locks: 1, errors: 1, sets: 1 });
  });
});

describe('RulesManagerComponent (D-789 section 10)', () => {
  const list = vi.fn();

  beforeEach(() => {
    list.mockReturnValue(of([
      rule({ id: 'r1', name: 'closed_lock', applies_to: 'roles', applies_to_nobody: true,
        roles: [{ id: 'x', name: 'Sales', portal_role: false, portal: null, live: true }],
        policies: [{ type: 'disabled', field: 'amount' }] }),
      rule({ id: 'r2', name: 'route', kind: 'routing', disabled_reason: 'field_deleted:region' }),
    ]));
    TestBed.configureTestingModule({
      imports: [RulesManagerComponent],
      providers: [
        {
          provide: BusinessRulesService,
          useValue: { list, get: vi.fn(), staffRoles: () => of([]), portalRoles: () => of([]) },
        },
        { provide: AdminService, useValue: { listEntities: () => of([]), getEntity: () => of({ attributes: [] }) } },
        { provide: LangService, useValue: { translate: (k: string) => k, errorText: () => 'error' } },
        // The owner-layer badge reads the editing layer.
        { provide: ChangesetContextService, useValue: { editingLayer: signal<string | null>(null) } },
      ],
    });
  });

  it('lists rules with their audience, summary and flags', () => {
    const fixture = TestBed.createComponent(RulesManagerComponent);
    fixture.detectChanges();
    const el = fixture.nativeElement as HTMLElement;
    const items = el.querySelectorAll('.item');
    expect(items.length).toBe(2);
    expect(items[0].textContent).toContain('Sales');
    expect(items[0].textContent).toContain('businessRules.list.locks');
    expect(items[0].textContent).toContain('businessRules.list.appliesToNobody');
    expect(items[1].textContent).toContain('businessRules.list.turnedOff');
    expect(list).toHaveBeenCalledWith({});
  });
});
