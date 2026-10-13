import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import { AuthService, LangService } from '@attome/base';
import { describe, expect, it } from 'vitest';
import { SidebarItem, SidebarPreferencesService } from '@attome/xrm/core/admin/data';
import { ShellSidebarComponent } from './shell-sidebar.component';

function item(partial: Partial<SidebarItem> & { id: string; name: string }): SidebarItem {
  return { icon: 'las la-cube', color: '', route: '', child: [], ...partial } as SidebarItem;
}

const TREE: SidebarItem[] = [
  item({
    id: 'sales', name: 'Sales',
    child: [item({ id: 'contacts', name: 'Contacts', route: '/xrm/sales/contact/list' })],
  }),
  item({
    id: 'ops', name: 'Ops',
    child: [item({ id: 'jobs', name: 'Jobs', route: '/xrm/ops/job/list' })],
  }),
];

// A real router (not a stub): the template renders `routerLink`/`routerLinkActive`,
// which resolve ActivatedRoute and call createUrlTree/serializeUrl on render.
function mount(): ComponentFixture<ShellSidebarComponent> {
  const language = signal<'en' | 'ar'>('en');
  TestBed.configureTestingModule({
    imports: [ShellSidebarComponent],
    providers: [
      provideRouter([]),
      { provide: AuthService, useValue: { userId: signal('user-id') } },
      { provide: LangService, useValue: { current: language, translate: (key: string) => key } },
      { provide: SidebarPreferencesService, useValue: { style: signal('classic') } },
    ],
  });
  return TestBed.createComponent(ShellSidebarComponent);
}

describe('ShellSidebarComponent localisation', () => {
  it('updates built-in labels immediately when the active language changes', () => {
    const fixture = mount();
    fixture.componentRef.setInput('items', [item({ id: 'dashboard', name: 'Dashboard', route: '/xrm/dashboard' })]);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Dashboard');

    TestBed.inject(LangService).current.set('ar');
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('لوحة التحكم');
    expect(fixture.nativeElement.textContent).not.toContain('Dashboard');
    expect(fixture.nativeElement.querySelector('.sidebar').getAttribute('dir')).toBe('rtl');
  });

  it('localises the newer module groups', () => {
    const fixture = mount();
    TestBed.inject(LangService).current.set('ar');
    fixture.componentRef.setInput('items', [
      item({ id: 'search', name: 'Search', child: [item({ id: 'report', name: 'Report', route: '/report' })] }),
      item({ id: 'ai', name: 'AI', route: '/ai' }),
    ]);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('البحث');
    expect(fixture.nativeElement.textContent).toContain('الذكاء الاصطناعي');
  });

  it('keeps custom sidebar names unchanged', () => {
    const fixture = mount();
    TestBed.inject(LangService).current.set('ar');
    fixture.componentRef.setInput('items', [item({ id: 'custom', name: 'Custom Area', route: '/custom' })]);
    fixture.detectChanges();
    expect(fixture.nativeElement.textContent).toContain('Custom Area');
  });
});

describe('ShellSidebarComponent auto-expand', () => {
  // The regression this pins: in ShellComponent the equivalent call ran inside
  // the sidebar fetch's subscribe callback, after the tree was already set.
  // Here the tree arrives as an input, so a one-shot ngOnInit call would run
  // against an empty array and silently never expand anything. The effect is
  // what makes a deep link land with its group open.
  it('expands the group containing the current route once items arrive', () => {
    const fixture = mount();
    const component = fixture.componentInstance;
    component.currentUrl.set('/xrm/ops/job/list');

    // Before the input lands there is nothing to expand.
    fixture.detectChanges();
    expect(component.isExpanded('ops')).toBe(false);

    fixture.componentRef.setInput('items', TREE);
    fixture.detectChanges();

    expect(component.isExpanded('ops')).toBe(true);
    expect(component.isExpanded('sales')).toBe(false);
  });

  it('leaves every group closed when the route matches none of them', () => {
    const fixture = mount();
    const component = fixture.componentInstance;
    component.currentUrl.set('/xrm/dashboard');

    fixture.componentRef.setInput('items', TREE);
    fixture.detectChanges();

    expect(component.isExpanded('ops')).toBe(false);
    expect(component.isExpanded('sales')).toBe(false);
  });

  it('keeps a manually expanded group open when the route changes', () => {
    const fixture = mount();
    const component = fixture.componentInstance;
    component.currentUrl.set('/xrm/ops/job/list');
    fixture.componentRef.setInput('items', TREE);
    fixture.detectChanges();

    component.toggleItem('sales');
    fixture.detectChanges();
    expect(component.isExpanded('sales')).toBe(true);

    // A later navigation adds its own group without collapsing the manual one.
    component.currentUrl.set('/xrm/sales/contact/list');
    fixture.detectChanges();

    expect(component.isExpanded('sales')).toBe(true);
    expect(component.isExpanded('ops')).toBe(true);
  });
});
