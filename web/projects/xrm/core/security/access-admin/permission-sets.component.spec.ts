import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { AdminService, FeatureFlagsService } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { PermissionSetsComponent, defaultSetAccess } from './permission-sets.component';
import {
  PermissionSetDetail,
  PermissionSetItem,
  SECURITY_FLAGS,
  SecurityAdminService,
  endOfDay,
} from '@attome/xrm/core/security';

const SET: PermissionSetItem = {
  id: 's1', name: 'Exports', name_ar: 'التصدير', description: null, row_version: 1, owner_layer: 'customer',
};
const DETAIL: PermissionSetDetail = { ...SET, privileges: ['contact.read'], entity_access: [] };

describe('PermissionSetsComponent', () => {
  let service: Record<string, ReturnType<typeof vi.fn>>;
  let flags: ReturnType<typeof signal<Record<string, boolean>>>;

  beforeEach(() => {
    flags = signal<Record<string, boolean>>({ [SECURITY_FLAGS.permissionSets]: true });
    service = {
      listPermissionSets: vi.fn().mockReturnValue(of([SET])),
      getPermissionSet: vi.fn().mockReturnValue(of(DETAIL)),
      listPermissionSetAssignments: vi.fn().mockReturnValue(of([])),
      listPrivileges: vi.fn().mockReturnValue(of([
        { id: 'p1', key: 'contact.read', name: 'Read contacts' },
        { id: 'p2', key: 'system.admin', name: 'Administer' },
        { id: 'p3', key: 'contact.export', name: 'Export contacts' },
      ])),
      listUsers: vi.fn().mockReturnValue(of({ items: [{ id: 'u1', is_active: true, email: 'a@x.test' }], total: 1, page: 1, page_size: 200 })),
      listTeams: vi.fn().mockReturnValue(of([])),
      assignPermissionSet: vi.fn().mockReturnValue(of({ id: 'a1', user_id: 'u1', created_at: '2026-10-27T00:00:00Z' })),
      setPermissionSetEntityAccess: vi.fn().mockReturnValue(of(defaultSetAccess('contact'))),
    };
    TestBed.configureTestingModule({
      imports: [PermissionSetsComponent],
      providers: [
        { provide: SecurityAdminService, useValue: service },
        { provide: AdminService, useValue: { listEntities: () => of([]) } },
        { provide: DialogService, useValue: { confirm: vi.fn().mockResolvedValue(true) } },
        { provide: FeatureFlagsService, useValue: { flags, ensureLoaded: () => undefined } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: () => 'en', intlLocale: () => 'en' } },
      ],
    });
    TestBed.overrideComponent(PermissionSetsComponent, { set: { template: '' } });
  });

  function create(): PermissionSetsComponent {
    const fixture = TestBed.createComponent(PermissionSetsComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  it('lists sets and never offers system administration', () => {
    const c = create();
    expect(c.sets()).toEqual([SET]);
    c.open(SET);
    expect(c.selected()).toEqual(DETAIL);
    expect(c.grantablePrivileges().map(p => p.key)).toEqual(['contact.export']);
  });

  it('is hidden until its switch is on', () => {
    flags.set({});
    const c = create();
    expect(c.enabled()).toBe(false);
  });

  it('sends no end date or reason while end dates are switched off', () => {
    const c = create();
    c.open(SET);
    c.assigneeId = 'u1';
    c.assignEndsOn = '2026-12-31';
    c.assignReason = 'audit';
    c.assign();
    expect(service['assignPermissionSet']).toHaveBeenCalledWith('s1', {
      user_id: 'u1', team_id: null, ends_at: null, reason: null,
    });
  });

  it('sends the end of the chosen day and the trimmed reason with end dates on', () => {
    flags.set({ [SECURITY_FLAGS.permissionSets]: true, [SECURITY_FLAGS.grantEndDates]: true });
    const c = create();
    c.open(SET);
    c.assignKind = 'team';
    c.assigneeId = 't1';
    c.assignEndsOn = '2026-12-31';
    c.assignReason = '  year-end audit ';
    c.assign();
    expect(service['assignPermissionSet']).toHaveBeenCalledWith('s1', {
      user_id: null, team_id: 't1', ends_at: endOfDay('2026-12-31'), reason: 'year-end audit',
    });
    expect(c.assignments().length).toBe(1);
  });

  it('keeps child units included when their toggles are hidden', () => {
    const c = create();
    c.open(SET);
    c.setAccess('entity', 'contact');
    c.setAccess('read_bu_children', false);
    c.saveAccess();
    const body = service['setPermissionSetEntityAccess'].mock.calls[0][1];
    expect(body.read_bu_children).toBe(true);
    expect(body.export_access_level).toBe(0);
  });

  it('turns a day into the end of that day', () => {
    const iso = endOfDay('2026-12-31');
    expect(iso).not.toBeNull();
    const end = new Date(iso as string);
    expect([end.getFullYear(), end.getMonth(), end.getDate(), end.getHours()]).toEqual([2026, 11, 31, 23]);
    expect(endOfDay('')).toBeNull();
  });
});
