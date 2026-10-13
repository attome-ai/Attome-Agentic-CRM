import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, OnDestroy, OnInit,
  signal, untracked,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { NavigationEnd, Router, RouterLink, RouterLinkActive } from '@angular/router';
import { Subscription } from 'rxjs';
import { filter } from 'rxjs/operators';
import { AuthService, LangService, TranslatePipe } from '@attome/base';
import { SidebarItem, SidebarPreferencesService } from '@attome/xrm/core/admin/data';

/**
 * The XRM shell's left navigation — the collapsible sidebar and, in `rail`
 * style, the fly-out panel that lists a group's children (D-315).
 *
 * Takes the sidebar tree as an input rather than fetching it: `ShellComponent`
 * still owns that request because quick search searches the same tree, and one
 * fetch feeding both is the point. Everything that is purely navigation state —
 * collapse, expansion, the rail selection, the filter box, and the route
 * tracking that keeps the active group open across navigations — lives here.
 *
 * `:host { display: contents }` is load-bearing: the sidebar and the rail panel
 * are two sibling flex children of the shell's `.xrm-layout`, and a host box
 * between them would break that row. `display: contents` removes the host box
 * while leaving both `<aside>` elements in the layout and the accessibility
 * tree exactly where they were. The layout custom properties
 * (`--sidebar-width`, `--sidebar-collapsed`, `--header-height`) still inherit
 * from the shell's `:host` through the DOM, which `display: contents` does not
 * interrupt.
 */
@Component({
  selector:   'xrm-shell-sidebar',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [RouterLink, RouterLinkActive, FormsModule, TranslatePipe],
  styleUrls: ['./shell-sidebar.component.css'],
  templateUrl: './shell-sidebar.component.html',
})
export class ShellSidebarComponent implements OnInit, OnDestroy {
  private readonly auth   = inject(AuthService);
  protected readonly lang = inject(LangService);
  private readonly router = inject(Router);
  private readonly sidebarPreferences = inject(SidebarPreferencesService);

  readonly items   = input<SidebarItem[]>([]);
  readonly loading = input(false);
  readonly error   = input(false);

  readonly entitySearch = signal('');
  readonly expandedIds  = signal<Set<string>>(new Set());
  readonly currentUrl   = signal(this.router.url.split('?')[0]);
  readonly isCollapsed  = signal(false);
  readonly railGroupId  = signal<string | null>(null);
  readonly railSearch   = signal('');

  private navSub?: Subscription;

  readonly sidebarStyle     = this.sidebarPreferences.style;
  readonly isRailStyle      = computed(() => this.sidebarStyle() === 'rail');
  readonly isSidebarCompact = computed(() => this.isRailStyle() || this.isCollapsed());

  readonly filteredFlat = computed(() => {
    const q = this.entitySearch().trim().toLowerCase();
    if (!q) return [] as { name: string; route: string; icon: string; is_disabled?: boolean }[];
    const flat: { name: string; route: string; icon: string; is_disabled?: boolean }[] = [];
    const collect = (items: SidebarItem[]) => {
      for (const item of items) {
        if (item.route) flat.push({ name: item.name, route: item.route, icon: item.icon, is_disabled: item.is_disabled });
        if (item.child.length) collect(item.child);
      }
    };
    collect(this.items());
    return flat.filter(i => this.displayName(i.name).toLowerCase().includes(q));
  });

  readonly railGroup = computed(() =>
    this.items().find(item => item.id === this.railGroupId()) ?? null
  );

  readonly filteredRailChildren = computed(() => {
    const query = this.railSearch().trim().toLowerCase();
    const children = this.railGroup()?.child ?? [];
    return query ? children.filter(child => this.displayName(child.name).toLowerCase().includes(query)) : children;
  });

  /**
   * Keeps the group containing the current route expanded.
   *
   * In `ShellComponent` this was called straight after the sidebar fetch
   * resolved. Here the tree arrives as an input instead, so the trigger is an
   * effect on `items()` + `currentUrl()` — otherwise the one call would run
   * against an empty tree and the active group would never open on a deep link
   * or reload. The write is `untracked` because `expandedIds.update()` reads
   * the signal it writes, which inside a tracking context would re-invalidate
   * this effect and loop.
   */
  private readonly autoExpandOnRoute = effect(() => {
    this.items();
    this.currentUrl();
    untracked(() => this.autoExpandActive());
  });

  ngOnInit(): void {
    this.navSub = this.router.events
      .pipe(filter(e => e instanceof NavigationEnd))
      .subscribe(() => this.currentUrl.set(this.router.url.split('?')[0]));
  }

  ngOnDestroy(): void {
    this.navSub?.unsubscribe();
  }

  /** Ensures the parent group containing the current route is expanded, so the
   *  sidebar reflects where navigation actually landed (e.g. a direct link or
   *  page reload into a nested route) instead of only reacting to manual toggles. */
  autoExpandActive(): void {
    const idsToExpand: string[] = [];
    const walk = (items: SidebarItem[]) => {
      for (const item of items) {
        if (item.child.length) {
          if (this.isItemActive(item)) idsToExpand.push(item.id);
          walk(item.child);
        }
      }
    };
    walk(this.items());
    if (!idsToExpand.length) return;
    this.expandedIds.update(set => {
      const next = new Set(set);
      idsToExpand.forEach(id => next.add(id));
      return next;
    });
  }

  toggleItem(id: string): void {
    this.expandedIds.update(set => {
      const next = new Set(set);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  expandSidebar(): void {
    if (this.isRailStyle()) {
      this.closeRailPanel();
      return;
    }
    this.isCollapsed.set(false);
  }

  openSidebarGroup(id: string): void {
    if (this.isRailStyle()) {
      this.railSearch.set('');
      this.railGroupId.update(current => current === id ? null : id);
      return;
    }
    if (this.isCollapsed()) {
      this.isCollapsed.set(false);
      this.expandedIds.update(set => new Set(set).add(id));
      return;
    }
    this.toggleItem(id);
  }

  closeRailPanel(): void {
    this.railGroupId.set(null);
    this.railSearch.set('');
  }

  isExpanded(id: string): boolean { return this.expandedIds().has(id); }

  isItemActive(item: SidebarItem): boolean {
    const url  = this.currentUrl();
    const base = item.route ? item.route.replace(/\/(list|form)$/, '') : '';
    if (base) return url.startsWith(base);
    return item.child.some(c => this.isItemActive(c));
  }

  routeLink(route: string): string[] {
    return route ? [route] : [];
  }

  /** Localise built-in navigation labels while preserving names created by admins. */
  displayName(name: string): string {
    if (this.lang.current() !== 'ar') return name;
    return ARABIC_SIDEBAR_LABELS[name] ?? name;
  }

  initial(): string { return (this.auth.userId() ?? 'U').slice(0, 1).toUpperCase(); }
  shortId(): string { return (this.auth.userId() ?? '').slice(0, 14); }
}

const ARABIC_SIDEBAR_LABELS: Readonly<Record<string, string>> = {
  'Dashboard': 'لوحة التحكم',
  'Access & Identity': 'الوصول والهوية',
  'Users': 'المستخدمون', 'Teams': 'الفرق', 'Organizations': 'المؤسسات', 'API Keys': 'مفاتيح واجهة البرمجة',
  'Security': 'الأمان', 'My Access': 'صلاحياتي', 'MFA Settings': 'إعدادات التحقق متعدد العوامل',
  'Privilege Grants': 'منح الصلاحيات', 'Role Privileges': 'صلاحيات الأدوار', 'Role Entity Access': 'وصول الأدوار للكيانات',
  'Field Security Profiles': 'ملفات أمان الحقول', 'User Access': 'وصول المستخدمين', 'Record Shares': 'مشاركة السجلات',
  'Management': 'الإدارة', 'Entity Manager': 'إدارة الكيانات', 'SQL Queries': 'استعلامات SQL', 'Views': 'العروض',
  'Sidebar Manager': 'إدارة الشريط الجانبي', 'Auto Value': 'القيم التلقائية', 'System Settings': 'إعدادات النظام',
  'Approval Queue': 'قائمة الموافقات', 'Data Protection': 'حماية البيانات', 'DSR Requests': 'طلبات حقوق البيانات',
  'Legal Holds': 'الحجوزات القانونية', 'Data Domains': 'مجالات البيانات', 'Master List': 'القائمة الرئيسية',
  'Knowledge Base': 'قاعدة المعرفة', 'Data Sources': 'مصادر البيانات', 'Data Items': 'عناصر البيانات',
  'System API': 'واجهة برمجة النظام', 'Clients': 'العملاء', 'S2S Clients (list)': 'عملاء خدمة إلى خدمة',
  'S2S Permissions': 'صلاحيات خدمة إلى خدمة', 'S2S Access Log': 'سجل وصول خدمة إلى خدمة',
  'Audit': 'التدقيق', 'Audit Log': 'سجل التدقيق', 'Audit Config': 'إعدادات التدقيق',
  'Audit Detail': 'تفاصيل التدقيق', 'Audit Snapshot': 'لقطة التدقيق', 'License': 'الترخيص',
  'Licenses': 'التراخيص', 'Import License': 'استيراد ترخيص', 'Module Management': 'إدارة الوحدات',
  'Feature Flags': 'أعلام الميزات', 'License Usage': 'استخدام الترخيص',
  'Notifications': 'الإشعارات', 'Templates': 'القوالب', 'Profiler': 'محلل الأداء', 'Failed Jobs': 'المهام الفاشلة',
  'Workflow': 'سير العمل', 'Definitions': 'التعريفات', 'Instances': 'المثيلات', 'State': 'الحالة', 'Search Lab': 'مختبر البحث',
  'Search': 'البحث', 'Report': 'التقارير', 'Document': 'المستندات', 'AI': 'الذكاء الاصطناعي',
  'Integration': 'التكامل', 'Localization': 'التوطين', 'View': 'العروض', 'Config': 'الإعدادات',
  'Bot': 'الروبوتات', 'Automation': 'الأتمتة', 'Generator': 'المولّد', 'Filter': 'تصفية',
  // SYSTEM-CHANGES.md Topic 15 #9 — the junction-table (`*_mm_*`) group,
  // seeded server-side by `sidebar_seed.rs`.
  'Relationships': 'العلاقات', 'User Teams': 'فرق المستخدمين', 'User Privileges': 'صلاحيات المستخدمين',
};
