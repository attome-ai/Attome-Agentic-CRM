import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { concat, forkJoin, last, Observable } from 'rxjs';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  AdminService, ModuleAdminService, ModuleConfiguration, ProjectSection, RuntimeModule, SidebarAdminItem,
} from '@attome/xrm/core/admin/data';
import { ToggleOption, ToggleOptionChange, ToggleOptionGridComponent } from '@attome/xrm/core/generic/components';

/** Y4-T5: the switched-on modules that need `name` on. Pure. */
export function dependantsOf(name: string, modules: readonly RuntimeModule[]): string[] {
  return modules
    .filter(module => module.enabled && module.name !== name && (module.depends_on ?? []).includes(name))
    .map(module => module.name);
}

/**
 * Module Management: the base platform modules (Y4-T5: with each one's
 * version, what it needs, who used it in 30 days, and a switch that will not
 * turn off a module another switched-on module needs), then each installed
 * project and its areas.
 */
@Component({
  selector: 'xrm-module-management',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [ToggleOptionGridComponent, TranslatePipe],
  styleUrls: ['../../../../styles/admin-page.css', './module-management.component.css'],
  templateUrl: './module-management.component.html',
})
export class ModuleManagementComponent {
  private readonly service = inject(ModuleAdminService);
  private readonly admin = inject(AdminService);
  readonly lang = inject(LangService);

  readonly loading = signal(true);
  readonly saving = signal(false);
  readonly enabled = signal(true);
  readonly modules = signal<RuntimeModule[]>([]);
  /** D-778: installed projects (verticals) and their areas, as edited. */
  readonly projects = signal<ProjectSection[]>([]);
  readonly error = signal<string | null>(null);
  readonly saved = signal(false);
  /** Why the last switch-off was refused, or `null`. */
  readonly refused = signal<string | null>(null);
  readonly moduleOptions = computed<ToggleOption[]>(() => {
    this.lang.current();
    const modules = this.modules();
    return modules.map(module => {
      const neededBy = dependantsOf(module.name, modules);
      return {
        id: module.name,
        title: this.displayName(module.name),
        description: this.moduleDescription(module.name),
        detail: this.moduleDetail(module, neededBy),
        icon: this.iconClass(module.name),
        active: module.enabled,
        locked: module.enabled && neededBy.length > 0,
      };
    });
  });

  /** Project and area visibility as loaded, to send only what changed. */
  private loadedActive = new Map<string, boolean>();
  /** Full sidebar rows: the PATCH replaces every field, so it needs them all. */
  private sidebarItems = new Map<string, SidebarAdminItem>();

  constructor() {
    this.load();
  }

  areaOptions(project: ProjectSection): ToggleOption[] {
    return project.areas.map(area => ({
      id: area.id,
      title: area.name,
      description: this.lang.translate('moduleMgmt.areaDesc', { name: area.name }),
      icon: this.sidebarItems.get(area.id)?.icon || 'las la-folder',
      active: area.is_active,
    }));
  }

  setProject(projectId: string, event: Event): void {
    const active = (event.target as HTMLInputElement).checked;
    this.projects.update(items => items.map(project =>
      project.id === projectId ? { ...project, is_active: active } : project));
    this.saved.set(false);
  }

  toggleArea(projectId: string, change: ToggleOptionChange): void {
    this.updateAreas(projectId, area => area.id === change.id ? change.active : area.is_active);
  }

  selectAllAreas(projectId: string, active: boolean): void {
    this.updateAreas(projectId, () => active);
  }

  private updateAreas(projectId: string, next: (area: ProjectSection['areas'][number]) => boolean): void {
    this.projects.update(items => items.map(project => project.id !== projectId ? project : {
      ...project,
      areas: project.areas.map(area => ({ ...area, is_active: next(area) })),
    }));
    this.saved.set(false);
  }

  private load(): void {
    forkJoin({
      config: this.service.getModuleConfiguration(),
      sidebar: this.admin.listSidebarAdmin(),
    }).subscribe({
      next: ({ config, sidebar }) => {
        this.apply(config, sidebar);
        this.loading.set(false);
      },
      error: (error: ApiError) => {
        this.error.set(error.message);
        this.loading.set(false);
      },
    });
  }

  private apply(config: ModuleConfiguration, sidebar: SidebarAdminItem[]): void {
    this.enabled.set(config.enabled);
    this.modules.set(config.modules);
    this.projects.set(config.projects ?? []);
    this.sidebarItems = new Map(sidebar.map(item => [item.id, item]));
    this.loadedActive = new Map();
    for (const project of config.projects ?? []) {
      this.loadedActive.set(project.id, project.is_active);
      for (const area of project.areas) this.loadedActive.set(area.id, area.is_active);
    }
  }

  /** One sidebar PATCH per project or area whose visibility changed. */
  private visibilityWrites(): Observable<unknown>[] {
    const changed: { id: string; active: boolean }[] = [];
    for (const project of this.projects()) {
      if (this.loadedActive.get(project.id) !== project.is_active) {
        changed.push({ id: project.id, active: project.is_active });
      }
      for (const area of project.areas) {
        if (this.loadedActive.get(area.id) !== area.is_active) {
          changed.push({ id: area.id, active: area.is_active });
        }
      }
    }
    return changed.flatMap(({ id, active }) => {
      const item = this.sidebarItems.get(id);
      if (!item) return [];
      return [this.admin.updateSidebarItem(id, {
        name: item.name,
        route: item.route,
        icon: item.icon,
        color: item.color,
        parent_ref: item.parent_ref,
        display_order: item.display_order,
        is_active: active,
        is_disabled: item.is_disabled,
        row_version: item.row_version,
        module_key: item.module_key,
        privilege_ids: item.privilege_ids,
      })];
    });
  }

  displayName(name: string): string { return name.replaceAll('_', ' '); }

  moduleDescription(name: string): string {
    const key = `moduleMgmt.desc.${name}`;
    const text = this.lang.translate(key);
    return text === key ? this.lang.translate('moduleMgmt.desc.other') : text;
  }

  iconClass(name: string): string {
    const icons: Record<string, string> = {
      core: 'las la-cube',
      workflow: 'las la-project-diagram',
      state: 'las la-flag',
      audit: 'las la-shield-alt',
      notification: 'las la-bell',
      search: 'las la-search',
      report: 'las la-chart-bar',
      document: 'las la-file-alt',
      ai: 'las la-brain',
      integration: 'las la-plug',
      localization: 'las la-language',
      view: 'las la-eye',
      config: 'las la-cog',
      bot: 'las la-robot',
      automation: 'las la-cogs',
      s2s: 'las la-key',
      license: 'las la-certificate',
      content: 'las la-file-code',
      project: 'las la-briefcase',
      service: 'las la-clipboard-check',
      dashboard: 'las la-tachometer-alt',
      grc: 'las la-gavel',
      process: 'las la-stream',
      docgen: 'las la-file-pdf',
      predict: 'las la-chart-pie',
      omnichannel: 'las la-comments',
    };

    return icons[name] ?? 'las la-puzzle-piece';
  }

  setMaster(event: Event): void {
    this.enabled.set((event.target as HTMLInputElement).checked);
    this.saved.set(false);
  }

  /** Version, what the module needs and who used it, as one line. */
  moduleDetail(module: RuntimeModule, neededBy: string[]): string {
    const parts: string[] = [];
    if (module.version) parts.push(this.lang.translate('moduleMgmt.version', { version: module.version }));
    if (module.depends_on?.length) {
      parts.push(this.lang.translate('moduleMgmt.needs', { modules: module.depends_on.map(n => this.displayName(n)).join(this.lang.translate('moduleMgmt.listSep')) }));
    }
    if (neededBy.length) {
      parts.push(this.lang.translate('moduleMgmt.neededBy', { modules: neededBy.map(n => this.displayName(n)).join(this.lang.translate('moduleMgmt.listSep')) }));
    }
    if (typeof module.active_users_30d === 'number') {
      parts.push(this.lang.translate('moduleMgmt.activeUsers', { count: module.active_users_30d }));
    }
    return parts.join(' · ');
  }

  toggle(change: ToggleOptionChange): void {
    if (!change.active) {
      const neededBy = dependantsOf(change.id, this.modules());
      if (neededBy.length) {
        this.refused.set(this.lang.translate('moduleMgmt.refused', {
          module: this.displayName(change.id),
          modules: neededBy.map(n => this.displayName(n)).join(this.lang.translate('moduleMgmt.listSep')),
        }));
        return;
      }
    }
    this.refused.set(null);
    this.modules.update(items => items.map(item =>
      item.name === change.id ? { ...item, enabled: change.active } : item));
    this.saved.set(false);
  }

  selectAll(enabled: boolean): void {
    this.modules.update(items => items.map(item => ({ ...item, enabled })));
    this.saved.set(false);
  }

  save(): void {
    this.saving.set(true);
    this.error.set(null);
    this.saved.set(false);
    const selected = this.modules()
      .filter(module => module.enabled)
      .map(module => module.name);
    // Sidebar writes run one at a time, then the module configuration; the
    // page reloads afterwards so every row version is current.
    concat(
      ...this.visibilityWrites(),
      this.service.updateModuleConfiguration(this.enabled(), selected),
    ).pipe(last()).subscribe({
      next: () => {
        this.saving.set(false);
        this.saved.set(true);
        this.load();
      },
      error: (error: ApiError) => {
        this.error.set(error.message);
        this.saving.set(false);
        this.load();
      },
    });
  }
}
