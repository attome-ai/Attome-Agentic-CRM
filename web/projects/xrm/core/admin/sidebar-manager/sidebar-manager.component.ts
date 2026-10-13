import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { forkJoin } from 'rxjs';
import { ApiError } from '@attome/base';

import {
  AdminService,
  ModuleAdminService,
  RuntimeModule,
  SidebarAdminItem,
  SidebarMutation,
  SidebarPrivilege,
} from '@attome/xrm/core/admin/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

@Component({
  selector: 'xrm-sidebar-manager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [OwnerLayerBadgeComponent, FormsModule],
  styleUrls: ['./sidebar-manager.component.css'],
  templateUrl: './sidebar-manager.component.html',
})
export class SidebarManagerComponent implements OnInit {
  private readonly service = inject(AdminService);
  private readonly moduleService = inject(ModuleAdminService);
  readonly items = signal<SidebarAdminItem[]>([]);
  readonly privileges = signal<SidebarPrivilege[]>([]);
  readonly modules = signal<RuntimeModule[]>([]);
  readonly loading = signal(true);
  readonly saving = signal(false);
  readonly error = signal('');
  readonly message = signal('');
  readonly selectedId = signal<string | null>(null);
  readonly editing = signal(false);
  readonly creating = signal(false);
  search = '';
  draft: SidebarMutation = this.blankDraft();

  readonly filtered = computed(() => {
    const query = this.search.trim().toLowerCase();
    return this.items().filter(item => !query || `${item.name} ${item.route ?? ''}`.toLowerCase().includes(query));
  });
  // The shell currently presents one expandable group level, so only roots
  // are valid parent choices in the editor even though the API tree is recursive.
  readonly parentOptions = computed(() => this.items().filter(item =>
    item.id !== this.selectedId() && item.parent_ref === null));

  ngOnInit(): void { this.reload(); }

  reload(): void {
    this.loading.set(true); this.error.set('');
    forkJoin({
      items: this.service.listSidebarAdmin(),
      privileges: this.service.listSidebarPrivileges(),
      modules: this.moduleService.getModuleConfiguration(),
    }).subscribe({
      next: result => {
        this.items.set(result.items);
        this.privileges.set(result.privileges);
        this.modules.set(result.modules.modules);
        this.loading.set(false);
      },
      error: (err: ApiError) => { this.error.set(err.message); this.loading.set(false); },
    });
  }

  parentName(item: SidebarAdminItem): string {
    return item.parent_ref ? this.items().find(parent => parent.id === item.parent_ref)?.name ?? 'Missing parent' : 'Top level';
  }

  select(item: SidebarAdminItem): void {
    this.selectedId.set(item.id); this.creating.set(false); this.editing.set(true); this.message.set(''); this.error.set('');
    this.draft = this.fromItem(item);
  }

  startCreate(): void {
    this.selectedId.set(null); this.creating.set(true); this.editing.set(true); this.message.set(''); this.error.set('');
    this.draft = this.blankDraft();
  }

  cancel(): void { this.editing.set(false); this.creating.set(false); this.selectedId.set(null); }
  hasPrivilege(id: string): boolean { return this.draft.privilege_ids.includes(id); }
  togglePrivilege(id: string): void {
    this.draft.privilege_ids = this.hasPrivilege(id)
      ? this.draft.privilege_ids.filter(value => value !== id)
      : [...this.draft.privilege_ids, id];
  }

  save(): void {
    this.saving.set(true); this.error.set(''); this.message.set('');
    const request = this.creating()
      ? this.service.createSidebarItem(this.draft)
      : this.service.updateSidebarItem(this.selectedId()!, this.draft);
    request.subscribe({
      next: saved => {
        this.items.update(items => this.creating() ? [...items, saved] : items.map(item => item.id === saved.id ? saved : item));
        this.saving.set(false); this.creating.set(false); this.selectedId.set(saved.id); this.draft = this.fromItem(saved);
        this.message.set('Sidebar item saved. Reload the shell to refresh navigation.');
      },
      error: (err: ApiError) => { this.error.set(err.message); this.saving.set(false); },
    });
  }

  deactivate(): void { this.draft.is_active = false; this.save(); }

  private fromItem(item: SidebarAdminItem): SidebarMutation {
    return { name:item.name, route:item.route, icon:item.icon, color:item.color, parent_ref:item.parent_ref,
      display_order:item.display_order, is_active:item.is_active, is_disabled:item.is_disabled, row_version:item.row_version,
      module_key:item.module_key, privilege_ids:[...item.privilege_ids] };
  }
  private blankDraft(): SidebarMutation {
    return { name:'', route:null, icon:'las la-circle', color:'#8b5cf6', parent_ref:null,
      display_order:300, is_active:true, is_disabled:false, module_key:null, privilege_ids:[] };
  }
}
