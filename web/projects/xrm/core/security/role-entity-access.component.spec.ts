import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { LangService } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { AdminService, FeatureFlagsService } from '@attome/xrm/core/admin/data';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { RoleEntityAccessComponent } from './role-entity-access.component';
import { SECURITY_FLAGS, SecurityAdminService } from './security-admin.service';

describe('RoleEntityAccessComponent', () => {
  let service: Record<string, ReturnType<typeof vi.fn>>;
  let flags: ReturnType<typeof signal<Record<string, boolean>>>;

  beforeEach(() => {
    flags = signal<Record<string, boolean>>({});
    service = {
      listEntityAccessGrants: vi.fn().mockReturnValue(of([])),
      listRoles: vi.fn().mockReturnValue(of([])),
      upsertEntityAccessGrant: vi.fn().mockImplementation((body: object) =>
        of({ id: 'g1', role_name: 'Rep', owner_layer: 'customer', ...body })),
    };
    TestBed.configureTestingModule({
      imports: [RoleEntityAccessComponent],
      providers: [
        provideRouter([]),
        { provide: SecurityAdminService, useValue: service },
        { provide: AdminService, useValue: { listEntities: () => of([]) } },
        { provide: DialogService, useValue: { confirm: vi.fn(), error: vi.fn() } },
        { provide: FeatureFlagsService, useValue: { flags, ensureLoaded: () => undefined } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: () => 'en' } },
      ],
    });
    TestBed.overrideComponent(RoleEntityAccessComponent, { set: { template: '' } });
  });

  function create(): RoleEntityAccessComponent {
    const fixture = TestBed.createComponent(RoleEntityAccessComponent);
    fixture.detectChanges();
    return fixture.componentInstance;
  }

  it('export_column_defaults_to_none', () => {
    const c = create();
    c.toggleCreate();
    c.newRoleId = 'r1';
    c.newEntity = 'contact';
    c.create();
    const body = service['upsertEntityAccessGrant'].mock.calls[0][0];
    expect(body.export_access_level).toBe(0);
    expect(body.bulk_access_level).toBe(0);
    // Create, assign and share follow the write level unless set.
    expect(body.create_access_level).toBeNull();
    expect(body.assign_access_level).toBeNull();
    expect(body.share_access_level).toBeNull();
    expect(c.grants()[0].export_access_level).toBe(0);
  });

  it('keeps child units included unless the switch shows the toggles', () => {
    const c = create();
    c.toggleCreate();
    c.newRoleId = 'r1';
    c.newEntity = 'contact';
    c.newChildren.read_bu_children = false;
    c.create();
    expect(service['upsertEntityAccessGrant'].mock.calls[0][0].read_bu_children).toBe(true);

    flags.set({ [SECURITY_FLAGS.childUnits]: true });
    c.toggleCreate();
    c.toggleCreate();
    c.newRoleId = 'r1';
    c.newEntity = 'contact';
    c.newChildren.read_bu_children = false;
    c.create();
    expect(service['upsertEntityAccessGrant'].mock.calls[1][0].read_bu_children).toBe(false);
  });

  it('labels an unset create level as following write', () => {
    const c = create();
    expect(c.optionalLevelLabel(null)).toBe('roleEntityAccess.sameAsWrite');
  });
});
