import { TestBed } from '@angular/core/testing';
import { of, Subject, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, provideAttomeI18n } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { provideXrmI18n } from '@attome/xrm/core/i18n';
import { AdminService } from '@attome/xrm/core/admin/data';

import { AuthPolicy, PortalAdminService, PortalDetail } from '../portal-admin.service';
import { PortalAdminComponent } from './portal-admin.component';

const portal: PortalDetail = {
  id: 'p1', name: 'Customers', keyword: 'customers', portal_type: 'authenticated',
  is_enabled: true, owning_team_ref: 't1', mfa_policy: 'optional', row_version: 1,
};
const page = <T>(items: T[], total = items.length) => ({ items, total, page: 1, page_size: 200 });
const policy: AuthPolicy = {
  signup_mode: 'invite_only', signup_domains: [], signup_role_ref: null, oidc_providers: [],
  terms_version: null, privacy_version: null, editable_profile_fields: ['phone'],
  page_size_cap: 100, allowed_cidrs: [], records_rpm: 600, username_min_len: 3, username_max_len: 12, username_blocked_words: [], username_reserved: [], trusted_server_login: false, row_version: 4,
};

const entities = [
  { id: 'e-case', logicalname: 'case', name: 'Case', is_active: true, is_append_only: false, attribute_count: 3 },
  { id: 'e-wpu', logicalname: 'webportal_user', name: 'Portal user', is_active: true, is_append_only: false, attribute_count: 3 },
  { id: 'e-user', logicalname: 'user_account', name: 'User', is_active: true, is_append_only: false, attribute_count: 3 },
];
const attr = (logicalname: string, field_type: string, lookup_entity_ref: string | null = null) => ({
  id: 'a-' + logicalname, entity_id: 'e-case', logicalname, name: logicalname, field_type, lookup_entity_ref,
  is_active: true, is_required: false, is_sensitive: false, is_sortable: true, is_filterable: true,
  is_write_restricted: false, data_classification: 'general', on_target_delete: 'orphan',
});

function setup(overrides: Partial<Record<keyof PortalAdminService, unknown>> = {}, confirm = false) {
  const admin = {
    listEntities: vi.fn(() => of(entities)),
    getEntity: vi.fn(() => of({ id: 'e-case', logicalname: 'case', name: 'Case', is_active: true, is_append_only: false,
      attributes: [attr('title', 'text'), attr('portal_user_ref', 'lookup', 'e-wpu'), attr('owner_ref', 'lookup', 'e-user')] })),
  };
  const service = {
    listTeams: vi.fn(() => of([{ id: 't1', name: 'Support' }])),
    createPortal: vi.fn(() => of({ ...portal, id: 'p2' })),
    putEntityConfig: vi.fn(() => of(undefined)),
    listPortals: vi.fn(() => of(page([portal]))),
    listUsers: vi.fn(() => of(page([{ id: 'u1', webportal_id: 'p1', name: 'Ann', email: 'ann@example.com', username: null, status: 'invited', row_version: 1 }]))),
    listRoles: vi.fn(() => of(page([{ id: 'r1', name: 'mine', user_count: 0 }]))),
    listEntityConfigs: vi.fn(() => of(page([]))),
    listErasureRequests: vi.fn(() => of(page([]))),
    getRole: vi.fn(() => of({ id: 'r1', webportal_id: 'p1', name: 'mine', user_count: 0, grants: [
      { entity: 'case', can_read: true, can_create: false, can_update: false, can_delete: false, public: true,
        conditions: [{ field: 'status', operator: 'eq', value: 1 }], fields: [] },
    ] })),
    putGrant: vi.fn(() => of(undefined)),
    getAuthPolicy: vi.fn(() => of(policy)),
    putAuthPolicy: vi.fn((_: string, body: AuthPolicy) => of({ ...body, row_version: body.row_version + 1 })),
    updateSettings: vi.fn(() => of({ ...portal, mfa_policy: 'required', row_version: 2 })),
    renameRole: vi.fn(() => of(undefined)),
    deleteRole: vi.fn(() => of(undefined)),
    unassignRole: vi.fn(() => of(undefined)),
    exportUser: vi.fn(() => of({ id: 'dsr-1', status: 'fulfilled', scopes: [
      { entity_logicalname: 'webportal_user', object_key: 'k', checksum: 'c', exported_rows: 1, withheld_for_legal_hold: 0 },
    ] })),
    ...overrides,
  };
  TestBed.configureTestingModule({
    imports: [PortalAdminComponent],
    providers: [
      { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
      provideAttomeI18n(),
      provideXrmI18n(),
      { provide: PortalAdminService, useValue: service },
      { provide: AdminService, useValue: admin },
      { provide: DialogService, useValue: { confirm: vi.fn(async () => confirm) } },
    ],
  });
  const fixture = TestBed.createComponent(PortalAdminComponent);
  fixture.detectChanges();
  return { fixture, service, admin, host: fixture.nativeElement as HTMLElement };
}

describe('PortalAdminComponent', () => {
  beforeEach(() => TestBed.resetTestingModule());

  it('lists portals and opens one on Manage', async () => {
    const { fixture, service, host } = setup();
    await fixture.whenStable();
    expect(host.textContent).toContain('customers');
    const manage = Array.from(host.querySelectorAll('button')).find(b => b.textContent?.includes('Manage'))!;
    manage.click();
    fixture.detectChanges();
    await fixture.whenStable();
    expect(service.listUsers).toHaveBeenCalledWith('p1');
    expect(host.textContent).toContain('ann@example.com');
  });

  it('labels a literal-only grant public and sends a bound condition as value_ref', async () => {
    const { fixture, service, host } = setup();
    const c = fixture.componentInstance;
    c.select(portal);
    c.openRole('r1');
    fixture.detectChanges();
    await fixture.whenStable();
    expect(host.querySelector('.badge-public')).not.toBeNull();

    c.grant.entity = 'case';
    c.grant.conditions = [{ field: 'portal_user_ref', operator: 'eq', value: '@portal_user.id' }];
    c.grant.fields = [{ field: 'title', can_read: true, can_write: true, can_filter: false }];
    c.saveGrant();
    expect(service.putGrant).toHaveBeenCalledWith('p1', 'r1', 'case', expect.objectContaining({
      conditions: [{ field: 'portal_user_ref', operator: 'eq', value_ref: '@portal_user.id' }],
    }));
  });

  it('parses a literal condition value as JSON when it can', () => {
    const { fixture } = setup();
    const c = fixture.componentInstance;
    c.grant.conditions = [{ field: 'status', operator: 'in', value: '[1,2]' }];
    expect(c.grantBody().conditions).toEqual([{ field: 'status', operator: 'in', value: [1, 2] }]);
  });

  it('sends up to three ANDed conditions and drops rows with no field', () => {
    const { fixture } = setup();
    const c = fixture.componentInstance;
    c.grant.conditions = [{ field: 'portal_user_ref', operator: 'eq', value: '@portal_user.id' }];
    c.addCondition();
    c.addCondition();
    c.addCondition(); // a fourth is refused
    expect(c.grant.conditions.length).toBe(3);
    c.grant.conditions[1] = { field: 'status', operator: 'ne', value: '99' };
    // row 3 left without a field
    expect(c.grantBody().conditions).toEqual([
      { field: 'portal_user_ref', operator: 'eq', value_ref: '@portal_user.id' },
      { field: 'status', operator: 'ne', value: 99 },
    ]);
    c.removeCondition(0);
    expect(c.grant.conditions[0].field).toBe('status');
  });

  it('loads every stored condition when a grant is edited', async () => {
    const { fixture } = setup({
      getRole: vi.fn(() => of({ id: 'r1', webportal_id: 'p1', name: 'mine', user_count: 0, grants: [
        { entity: 'case', can_read: true, can_create: false, can_update: false, can_delete: false, public: false,
          conditions: [
            { field: 'portal_user_ref', operator: 'eq', value_ref: '@portal_user.id' },
            { field: 'status', operator: 'ne', value: 99 },
          ], fields: [] },
      ] })),
    });
    const c = fixture.componentInstance;
    c.select(portal);
    c.openRole('r1');
    await fixture.whenStable();
    c.editGrant('case');
    expect(c.grant.conditions).toEqual([
      { field: 'portal_user_ref', operator: 'eq', value: '@portal_user.id' },
      { field: 'status', operator: 'ne', value: '99' },
    ]);
  });

  it('saves settings with the row version, sending the keyword only when it changed', async () => {
    const { fixture, service } = setup();
    const c = fixture.componentInstance;
    c.select(portal);
    await fixture.whenStable();
    c.settings()!.mfa_policy = 'required';
    c.settings()!.owning_team_ref = '';
    c.saveSettings();
    expect(service.updateSettings).toHaveBeenCalledWith('p1', {
      row_version: 1, portal_type: 'authenticated', is_enabled: true, owning_team_ref: null, mfa_policy: 'required',
    });
    expect(c.selected()?.row_version).toBe(2);

    c.settings()!.keyword = 'customers-2';
    c.saveSettings();
    expect(service.updateSettings).toHaveBeenLastCalledWith('p1', expect.objectContaining({ keyword: 'customers-2' }));
  });

  it('edits the account policy as one item per line', async () => {
    const { fixture, service, host } = setup();
    const c = fixture.componentInstance;
    c.select(portal);
    fixture.detectChanges();
    await fixture.whenStable();
    expect(host.querySelector('#pp-mode')).not.toBeNull();
    expect(c.policyDraft()?.editable_profile_fields).toBe('phone');

    c.policyDraft()!.signup_mode = 'domain_allowlist';
    c.policyDraft()!.signup_domains = 'Example.com\n\n acme.test ';
    c.policyDraft()!.allowed_cidrs = '10.0.0.0/8, 192.168.1.1';
    c.savePolicy();
    expect(service.putAuthPolicy).toHaveBeenCalledWith('p1', expect.objectContaining({
      signup_mode: 'domain_allowlist',
      signup_domains: ['example.com', 'acme.test'],
      allowed_cidrs: ['10.0.0.0/8', '192.168.1.1'],
      editable_profile_fields: ['phone'],
      row_version: 4,
    }));
    expect(c.policy()?.row_version).toBe(5);
  });

  it('keeps the username rules when saving the policy (the server replaces it whole)', async () => {
    const { fixture, service } = setup({
      getAuthPolicy: vi.fn(() => of({
        ...policy,
        username_min_len: 4, username_max_len: 16,
        username_blocked_words: ['rude'], username_reserved: ['admin', 'support'],
      })),
    });
    const c = fixture.componentInstance;
    c.select(portal);
    fixture.detectChanges();
    await fixture.whenStable();
    expect(c.policyDraft()?.username_reserved).toBe('admin\nsupport');

    c.policyDraft()!.username_blocked_words = 'rude\nworse ';
    c.savePolicy();
    expect(service.putAuthPolicy).toHaveBeenCalledWith('p1', expect.objectContaining({
      username_min_len: 4,
      username_max_len: 16,
      username_blocked_words: ['rude', 'worse'],
      username_reserved: ['admin', 'support'],
    }));
  });

  it('renames and, after confirmation, deletes a role; unassigns a user role', async () => {
    const { fixture, service } = setup({}, true);
    const c = fixture.componentInstance;
    c.select(portal);
    c.openRole('r1');
    await fixture.whenStable();
    c.roleName = 'mine-renamed';
    c.renameRole();
    expect(service.renameRole).toHaveBeenCalledWith('p1', 'r1', 'mine-renamed');

    await c.deleteRole();
    expect(service.deleteRole).toHaveBeenCalledWith('p1', 'r1');
    expect(c.role()).toBeNull();

    c.unassignRole({ id: 'u1', webportal_id: 'p1', name: 'Ann', email: 'ann@example.com', username: null, status: 'active', row_version: 1 });
    expect(service.unassignRole).toHaveBeenCalledWith('p1', 'u1');
  });

  it('renders a policy that arrives after the portal opened, and drops a late answer for another portal', async () => {
    const answers: Record<string, Subject<AuthPolicy>> = { p1: new Subject(), p2: new Subject() };
    const { fixture, host } = setup({ getAuthPolicy: vi.fn((id: string) => answers[id]) });
    const c = fixture.componentInstance;
    c.select(portal);
    fixture.detectChanges();
    await fixture.whenStable();
    expect(host.querySelector('#pp-mode')).toBeNull();

    // A second portal opens before the first one's policy arrives.
    c.select({ ...portal, id: 'p2', keyword: 'partners' });
    answers['p2'].next({ ...policy, signup_mode: 'self_service', row_version: 9 });
    answers['p1'].next({ ...policy, signup_mode: 'domain_allowlist', row_version: 1 });
    fixture.detectChanges();
    await fixture.whenStable();
    expect(c.policyDraft()?.signup_mode).toBe('self_service');
    expect(c.policy()?.row_version).toBe(9);
    expect(host.querySelector('#pp-mode')).not.toBeNull();
  });

  it('explains a 409 by its cause', async () => {
    const { fixture, host } = setup({
      deleteRole: vi.fn(() => throwError(() => ({ kind: 'conflict', message: '', status: 409 }))),
    }, true);
    const c = fixture.componentInstance;
    c.select(portal);
    c.openRole('r1');
    await fixture.whenStable();
    await c.deleteRole();
    fixture.detectChanges();
    expect(host.querySelector('[role="alert"]')?.textContent).toContain('still held by users');
    expect(c.role()).not.toBeNull();
  });

  it('keeps a role when the delete is not confirmed', async () => {
    const { fixture, service } = setup();
    const c = fixture.componentInstance;
    c.select(portal);
    c.openRole('r1');
    await fixture.whenStable();
    await c.deleteRole();
    expect(service.deleteRole).not.toHaveBeenCalled();
    expect(c.role()).not.toBeNull();
  });

  it('reports the export and shows an API error as an alert', async () => {
    const { fixture, host, service } = setup({
      listPortals: vi.fn(() => throwError(() => ({ kind: 'forbidden', message: '' }))),
    });
    await fixture.whenStable();
    fixture.detectChanges();
    expect(host.querySelector('[role="alert"]')).not.toBeNull();

    const c = fixture.componentInstance;
    c.select(portal);
    c.exportData({ id: 'u1', webportal_id: 'p1', name: 'Ann', email: 'ann@example.com', username: null, status: 'active', row_version: 1 });
    fixture.detectChanges();
    expect(service.exportUser).toHaveBeenCalledWith('p1', 'u1');
    // The ICU formatter loads lazily and is not there in a unit test, so the
    // message's parameters are not asserted here; the status region is.
    expect(host.querySelector('[role="status"]')?.textContent).toContain('Export done');
    expect(host.querySelector('[role="alert"]')).toBeNull();
  });
  it('picks the owning team by name and submits its id', async () => {
    const { fixture, service, host } = setup();
    await fixture.whenStable();
    fixture.detectChanges();
    const options = Array.from(host.querySelectorAll<HTMLOptionElement>('#np-team option'));
    expect(options.map(o => o.textContent?.trim())).toContain('Support');
    const c = fixture.componentInstance;
    c.newPortal = { name: 'Partners', keyword: 'partners', portal_type: 'authenticated', is_enabled: true, owning_team_ref: 't1' };
    c.createPortal();
    expect(service.createPortal).toHaveBeenCalledWith(expect.objectContaining({ owning_team_ref: 't1' }));
  });

  it('offers only portal-exposable entities and only lookups onto the portal user as the portal user field', async () => {
    const { fixture, service, admin, host } = setup();
    const c = fixture.componentInstance;
    c.select(portal);
    fixture.detectChanges();
    await fixture.whenStable();
    expect(c.entities().map(e => e.logicalname)).toEqual(['case']);
    expect(host.querySelectorAll('#portal-entity-options option').length).toBe(1);

    // A typed display name resolves to the logical name.
    c.entityConfig.entity = 'Case';
    c.onConfigEntityChange('Case');
    expect(admin.getEntity).toHaveBeenCalledWith('e-case');
    expect(c.portalUserFields().map(a => a.logicalname)).toEqual(['portal_user_ref']);

    c.entityConfig.portal_user_field = 'portal_user_ref';
    c.saveEntityConfig();
    expect(service.putEntityConfig).toHaveBeenCalledWith('p1', 'case', 'portal_user_ref');
  });

  it('pages past the first 200 users with Load more', async () => {
    const first = Array.from({ length: 200 }, (_, i) => ({
      id: 'u' + i, webportal_id: 'p1', name: 'U' + i, email: `u${i}@example.com`, username: null, status: 'active', row_version: 1,
    }));
    const listUsers = vi.fn((_: string, n = 1) => of(n === 1
      ? page(first, 201)
      : { items: [{ id: 'u200', webportal_id: 'p1', name: 'Last', email: 'last@example.com', username: null, status: 'active', row_version: 1 }],
          total: 201, page: 2, page_size: 200 }));
    const { fixture, host } = setup({ listUsers });
    const c = fixture.componentInstance;
    c.select(portal);
    fixture.detectChanges();
    await fixture.whenStable();
    const more = Array.from(host.querySelectorAll('button')).find(b => b.textContent?.includes('Load more'))!;
    expect(more).toBeTruthy();
    more.click();
    fixture.detectChanges();
    expect(listUsers).toHaveBeenLastCalledWith('p1', 2);
    expect(c.users().length).toBe(201);
    expect(Array.from(host.querySelectorAll('button')).some(b => b.textContent?.includes('Load more'))).toBe(false);
  });
});
