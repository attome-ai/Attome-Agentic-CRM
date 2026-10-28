import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AdminService, ModuleAdminService, type ModuleConfiguration, type SidebarAdminItem,
} from '@attome/xrm/core/admin/data';
import { ModuleManagementComponent, dependantsOf } from './module-management.component';

describe('ModuleManagementComponent', () => {
  const svc = {
    getModuleConfiguration: vi.fn(),
    updateModuleConfiguration: vi.fn(),
  };
  const admin = {
    listSidebarAdmin: vi.fn(),
    updateSidebarItem: vi.fn(),
  };

  // D-778: no licence, so every module is switchable, and each installed
  // project (vertical) is its own section of sidebar areas.
  const CONFIG: ModuleConfiguration = {
    enabled: true,
    modules: [
      { name: 'workflow', enabled: true, licensed: true },
      { name: 'audit', enabled: false, licensed: true },
      { name: 'trd', enabled: true, licensed: true },
    ],
    projects: [{
      id: 'game-ops', name: 'Game Ops', is_active: true, row_version: 3,
      areas: [
        { id: 'bans', name: 'Bans', is_active: true, row_version: 5 },
        { id: 'servers', name: 'Servers', is_active: false, row_version: 2 },
      ],
    }],
  };

  const row = (id: string, name: string, is_active: boolean, row_version: number): SidebarAdminItem => ({
    id, name, route: `/xrm/${id}`, icon: 'las la-ban', color: '#8b5cf6',
    parent_ref: id === 'game-ops' ? null : 'game-ops', display_order: 1,
    is_active, is_disabled: false, row_version, module_key: null, privilege_ids: ['p1'], owner_layer: 'project',
  });
  const SIDEBAR: SidebarAdminItem[] = [
    row('game-ops', 'Game Ops', true, 3),
    row('bans', 'Bans', true, 5),
    row('servers', 'Servers', false, 2),
  ];

  function mount(config: ModuleConfiguration) {
    svc.getModuleConfiguration.mockReturnValue(of(config));
    svc.updateModuleConfiguration.mockReturnValue(of(config));
    admin.listSidebarAdmin.mockReturnValue(of(SIDEBAR));
    admin.updateSidebarItem.mockImplementation((id: string) => of(SIDEBAR.find(item => item.id === id)));
    TestBed.configureTestingModule({
      providers: [
        { provide: ModuleAdminService, useValue: svc },
        { provide: AdminService, useValue: admin },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
            current: signal('en'),
          },
        },
      ],
    });
    TestBed.overrideComponent(ModuleManagementComponent, { set: { template: '' } });
    const fixture = TestBed.createComponent(ModuleManagementComponent);
    fixture.detectChanges();
    return fixture;
  }

  beforeEach(() => {
    for (const fn of [...Object.values(svc), ...Object.values(admin)]) fn.mockReset();
  });

  it('save sends every enabled base module, with no licence filter', () => {
    const fixture = mount(CONFIG);

    fixture.componentInstance.save();

    expect(svc.updateModuleConfiguration).toHaveBeenCalledWith(true, ['workflow', 'trd']);
  });

  it('selectAll enables every base module', () => {
    const fixture = mount(CONFIG);
    const c = fixture.componentInstance;

    c.selectAll(true);

    expect(c.modules().every(module => module.enabled)).toBe(true);
  });

  it('shows one section per project with its areas', () => {
    const fixture = mount(CONFIG);
    const c = fixture.componentInstance;
    const [project] = c.projects();

    expect(project.name).toBe('Game Ops');
    expect(c.areaOptions(project).map(o => [o.title, o.active])).toEqual([
      ['Bans', true],
      ['Servers', false],
    ]);
  });

  it('save patches only the areas whose visibility changed, with the full row', () => {
    const fixture = mount(CONFIG);
    const c = fixture.componentInstance;

    c.toggleArea('game-ops', { id: 'bans', active: false });
    c.save();

    expect(admin.updateSidebarItem).toHaveBeenCalledTimes(1);
    expect(admin.updateSidebarItem).toHaveBeenCalledWith('bans', expect.objectContaining({
      name: 'Bans', is_active: false, row_version: 5, privilege_ids: ['p1'], route: '/xrm/bans',
    }));
    expect(svc.updateModuleConfiguration).toHaveBeenCalled();
  });

  it('turning a project off patches its root row', () => {
    const fixture = mount(CONFIG);
    const c = fixture.componentInstance;

    c.setProject('game-ops', { target: { checked: false } } as unknown as Event);
    c.save();

    expect(admin.updateSidebarItem).toHaveBeenCalledWith('game-ops', expect.objectContaining({
      is_active: false, row_version: 3,
    }));
  });

  // Y4-T5: versions, dependencies and usage, and the dependency refusal.
  const WITH_DEPS: ModuleConfiguration = {
    enabled: true,
    modules: [
      { name: 'project', enabled: true, licensed: true, version: '0.1.0', depends_on: [], active_users_30d: 4 },
      { name: 'service', enabled: true, licensed: true, version: '0.1.0', depends_on: ['project'], active_users_30d: 2 },
      { name: 'grc', enabled: false, licensed: true, version: '0.1.0', depends_on: ['project'], active_users_30d: null },
    ],
    projects: [],
  };

  it('dependantsOf names only the switched-on modules that need it', () => {
    expect(dependantsOf('project', WITH_DEPS.modules)).toEqual(['service']);
    expect(dependantsOf('service', WITH_DEPS.modules)).toEqual([]);
  });

  it('refuses to switch off a module a switched-on module needs, naming it', () => {
    const fixture = mount(WITH_DEPS);
    const c = fixture.componentInstance;

    c.toggle({ id: 'project', active: false });

    expect(c.modules().find(m => m.name === 'project')?.enabled).toBe(true);
    expect(c.refused()).toContain('moduleMgmt.refused');
    expect(c.refused()).toContain('service');
    c.save();
    expect(svc.updateModuleConfiguration).toHaveBeenCalledWith(true, ['project', 'service']);
  });

  it('allows it once the dependants are off, and locks the switch until then', () => {
    const fixture = mount(WITH_DEPS);
    const c = fixture.componentInstance;
    expect(c.moduleOptions().find(o => o.id === 'project')?.locked).toBe(true);

    c.toggle({ id: 'service', active: false });
    expect(c.moduleOptions().find(o => o.id === 'project')?.locked).toBe(false);
    c.toggle({ id: 'project', active: false });

    expect(c.refused()).toBeNull();
    expect(c.modules().find(m => m.name === 'project')?.enabled).toBe(false);
  });

  it('shows the version, what a module needs and its users in 30 days', () => {
    const fixture = mount(WITH_DEPS);
    const detail = fixture.componentInstance.moduleOptions().find(o => o.id === 'service')?.detail ?? '';

    expect(detail).toContain('moduleMgmt.version {"version":"0.1.0"}');
    expect(detail).toContain('moduleMgmt.needs');
    expect(detail).toContain('moduleMgmt.activeUsers {"count":2}');
  });
});
