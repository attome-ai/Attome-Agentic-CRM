import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ApiService, AuthService, BrandService, CommandRegistry, LangService, ThemeService } from '@attome/base';
import { of, Subject } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { AdminService } from '@attome/xrm/core/admin/data';
import { SidebarPreferencesService } from '@attome/xrm/core/admin/data';
import { ShellComponent } from './shell.component';

function createComponent() {
  const navigate = vi.fn();
  // The palette ranks by stored use counts; each test starts without any.
  localStorage.removeItem('attome.palette.uses');
  TestBed.configureTestingModule({
    providers: [
      { provide: AuthService, useValue: { userId: signal('user-id'), logout: () => of(undefined) } },
      { provide: ApiService, useValue: { post: () => of({}) } },
      { provide: BrandService, useValue: { loadMine: vi.fn() } },
      { provide: AdminService, useValue: { getSidebar: () => of([]) } },
      {
        provide: Router,
        useValue: { url: '/xrm', events: new Subject(), navigate, navigateByUrl: vi.fn() },
      },
      { provide: SidebarPreferencesService, useValue: { style: signal('classic') } },
      {
        provide: ThemeService,
        useValue: { mode: signal('light'), setMode: vi.fn() },
      },
      { provide: LangService, useValue: { current: signal('en'), set: vi.fn(), translate: (key: string) => key } },
    ],
  });
  const component = TestBed.runInInjectionContext(() => new ShellComponent());
  component.sidebarItems.set([
    { id: 'accounts', name: 'Accounts', icon: 'las la-building', color: '', route: '/xrm/entity/account/list', child: [] },
    { id: 'contacts', name: 'Contacts', icon: 'las la-user', color: '', route: '/xrm/entity/contact/list', child: [] },
  ]);
  component.qsQuery.set('c');
  component.quickSearchOpen.set(true);
  return { component, navigate };
}

describe('ShellComponent quick search keyboard navigation', () => {
  it('navigates to the selected result when Enter comes from the search input', () => {
    const { component, navigate } = createComponent();
    component.qsActive.set(1);
    const event = new KeyboardEvent('keydown', { key: 'Enter', bubbles: true });
    const preventDefault = vi.spyOn(event, 'preventDefault');
    const stopPropagation = vi.spyOn(event, 'stopPropagation');

    component.onQuickSearchKeydown(event);

    expect(preventDefault).toHaveBeenCalled();
    expect(stopPropagation).toHaveBeenCalled();
    expect(navigate).toHaveBeenCalledWith(['/xrm/entity/contact/list']);
    expect(component.quickSearchOpen()).toBe(false);
  });

  it('moves the selected result down and up, wrapping at each end', () => {
    const { component } = createComponent();
    component.qsActive.set(0);

    component.onQuickSearchKeydown(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    expect(component.qsActive()).toBe(1);

    component.onQuickSearchKeydown(new KeyboardEvent('keydown', { key: 'ArrowDown' }));
    expect(component.qsActive()).toBe(0);

    component.onQuickSearchKeydown(new KeyboardEvent('keydown', { key: 'ArrowUp' }));
    expect(component.qsActive()).toBe(1);
  });
});

// M65 Phase 1 (D-467) — "apps only filter, never authorize": the switcher's
// selection narrows `filteredSidebarItems`, a pure view over `sidebarItems`,
// nothing more.
describe('ShellComponent app switcher filter', () => {
  it('shows the full tree when no app is selected (the default)', () => {
    const { component } = createComponent();
    expect(component.filteredSidebarItems()).toBe(component.sidebarItems());
  });

  it('keeps only sidebar items whose route resolves to a selected entity, and drops empty groups', () => {
    const { component } = createComponent();
    component.sidebarItems.set([
      {
        id: 'sales', name: 'Sales', icon: '', color: '', route: '',
        child: [
          { id: 'accounts', name: 'Accounts', icon: '', color: '', route: '/xrm/entity/account/list', child: [] },
          { id: 'contacts', name: 'Contacts', icon: '', color: '', route: '/xrm/entity/contact/list', child: [] },
        ],
      },
      {
        id: 'reports', name: 'Reports', icon: '', color: '', route: '',
        child: [
          { id: 'sales-dash', name: 'Sales dashboard', icon: '', color: '', route: '/xrm/dashboard/sales', child: [] },
        ],
      },
      {
        id: 'security', name: 'Security', icon: '', color: '', route: '',
        child: [
          { id: 'roles', name: 'Roles', icon: '', color: '', route: '/xrm/entity/role/list', child: [] },
        ],
      },
    ]);

    component.onAppChanged(['account']);

    const filtered = component.filteredSidebarItems();
    // 'security' is dropped entirely: its only child is a recognizable
    // entity route ('role') that isn't in the selected app.
    expect(filtered.map(g => g.id)).toEqual(['sales', 'reports']);
    expect(filtered[0].child.map(c => c.id)).toEqual(['accounts']);
    // A non-entity route (no recognizable `entityListRoute` shape) is never
    // guessed at, so its group survives the filter untouched.
    expect(filtered[1].child.map(c => c.id)).toEqual(['sales-dash']);
  });

  it('clearing the selection (null) restores the unfiltered tree', () => {
    const { component } = createComponent();
    component.onAppChanged(['account']);
    component.onAppChanged(null);
    expect(component.filteredSidebarItems()).toBe(component.sidebarItems());
  });
});

describe('ShellComponent header record search (U13)', () => {
  it('opens the selected record through the entity form route', () => {
    const { component, navigate } = createComponent();

    component.openSearchHit({
      hit: {
        entity_logicalname: 'user_account', record_id: '0190a1b2-0000-7000-8000-000000000001',
        matched_legs: ['fts'], score: 1, title: 'Jane',
      },
      rank: 0,
      impressionId: null,
    });

    expect(navigate).toHaveBeenCalledWith(['/xrm', 'entity', 'user_account', 'form'], {
      queryParams: { id: '0190a1b2-0000-7000-8000-000000000001' },
    });
  });
});

describe('ShellComponent command palette (B10-T1)', () => {
  it('opens on Ctrl+K', () => {
    const { component } = createComponent();
    component.quickSearchOpen.set(false);
    component.onKeydown(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true }));
    expect(component.quickSearchOpen()).toBe(true);
  });

  it('lists the open page's commands first, and only commands after >', () => {
    const { component } = createComponent();
    const run = vi.fn();
    TestBed.inject(CommandRegistry).register(
      { id: 'other', labelKey: 'Clear cache', run: vi.fn() },
      { id: 'save', labelKey: 'Save contact', context: true, run },
    );
    component.qsQuery.set('c');
    expect(component.qsResults()[0].id).toBe('cmd:save');
    expect(component.qsResults().map(r => r.id)).toContain('contacts');

    component.qsQuery.set('>');
    expect(component.qsResults().map(r => r.id)).toEqual(['cmd:save', 'cmd:other']);

    component.navigateTo(component.qsResults()[0]);
    expect(run).toHaveBeenCalled();
    expect(component.quickSearchOpen()).toBe(false);
  });

  it('ranks what this person picks most', () => {
    const { component } = createComponent();
    component.qsQuery.set('c');
    const contacts = component.qsResults().find(r => r.id === 'contacts');
    if (!contacts) throw new Error('Contacts should match "c"');
    component.navigateTo(contacts);
    component.quickSearchOpen.set(true);
    component.qsQuery.set('c');
    expect(component.qsResults()[0].id).toBe('contacts');
  });
});
