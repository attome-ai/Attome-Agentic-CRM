import {
  ChangeDetectionStrategy, Component, ElementRef, HostListener, OnInit, computed, effect, inject,
  input, signal, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { forkJoin } from 'rxjs';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { EntityService } from '../services/entity.service';

interface TeamRoleItem {
  id:        string;
  team_id:   string;
  role_id:   string;
  role_name: string;
}

interface RoleOption {
  id:   string;
  name: string;
}

/**
 * "Roles" tab for the Team form — every role assigned to a team (D-133:
 * "everyone on this team gets this role"). Presented as the same grid +
 * picker-dialog pattern as the Users tab's `xrm-related-grid`
 * (`entity-form.component.ts`'s "roles"/"users" panels), but it cannot
 * actually *be* one: the backing junction table `role_mm_team` is
 * infrastructure-only (migration 0051), never registered through
 * `ensure_entity` (see `attome-security/src/seed.rs` and `admin/teams.rs`'s
 * module doc), so the generic entity API has no schema for it — and
 * `add_team_role`/`remove_team_role` invalidate every affected member's
 * cached SecurityContext (`invalidate_sync_all`), which raw generic CRUD on
 * the junction table would silently skip. Reads/writes therefore go through
 * the existing bespoke admin endpoints (`/api/v1/admin/security/teams/{id}/roles`)
 * via `ApiService` directly rather than `SecurityAdminService` — this
 * component lives in `@attome/xrm/entity`, which `@attome/xrm/security` does
 * not depend on, and pulling that whole entry point in for three endpoint
 * calls would cost far more bundle weight than it is worth (same reasoning
 * as `user-account-state.actions.ts`'s `ApiService`-over-`SecurityAdminService`
 * choice, forms/user/user-account-state.actions.ts).
 */
@Component({
  selector: 'xrm-team-roles-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../../styles/xrm-form.css', './team-roles-panel.component.css'],
  templateUrl: './team-roles-panel.component.html',
})
export class TeamRolesPanelComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly entitySvc = inject(EntityService);
  private readonly pickerSearchInput = viewChild<ElementRef<HTMLInputElement>>('pickerSearchInput');

  readonly teamId = input.required<string>();

  readonly roles = signal<TeamRoleItem[]>([]);
  readonly allRoles = signal<RoleOption[]>([]);
  readonly loading = signal(false);
  readonly removingId = signal<string | null>(null);
  readonly error = signal('');

  readonly pickerOpen = signal(false);
  readonly pickerSearch = signal('');
  readonly pickerSelection = signal<Set<string>>(new Set());
  readonly pickerSaving = signal(false);
  readonly pickerError = signal('');

  /** Roles not yet on the team, filtered by the picker's search box — computed
   * client-side over `allRoles()` rather than a debounced server round trip:
   * the role catalog is an admin-defined, bounded set (realistically dozens,
   * same "hundreds at most" assumption `ApiService.MAX_ALL_PAGES_ITEMS`'s
   * comment makes for role/team/grant admin screens), so a substring filter
   * over the already-fetched list is both simpler and faster than a network
   * round trip per keystroke. */
  readonly pickerItems = computed<RoleOption[]>(() => {
    const assigned = new Set(this.roles().map(r => r.role_id));
    const q = this.pickerSearch().trim().toLowerCase();
    return this.allRoles()
      .filter(r => !assigned.has(r.id))
      .filter(r => !q || r.name.toLowerCase().includes(q));
  });

  constructor() {
    effect(() => {
      const id = this.teamId();
      if (id) this.load(id);
    });
    effect(() => {
      if (this.pickerOpen()) {
        setTimeout(() => this.pickerSearchInput()?.nativeElement.focus(), 0);
      }
    });
  }

  ngOnInit(): void {
    this.entitySvc.list('role', { limit: 200, sorts: [{ field: 'name', dir: 'asc' }] })
      .subscribe({
        next: res => this.allRoles.set(res.data.map(r => ({ id: r.id, name: String(r.data['name'] ?? r.id) }))),
        error: () => this.error.set('Could not load the role catalog.'),
      });
  }

  @HostListener('document:keydown.escape')
  onEscape(): void {
    if (this.pickerOpen()) this.closePicker();
  }

  private load(teamId: string): void {
    this.loading.set(true);
    this.error.set('');
    this.api.getAllPages<TeamRoleItem>(`/api/v1/admin/security/teams/${teamId}/roles`).subscribe({
      next: rows => {
        this.roles.set(rows);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
        this.error.set('Could not load this team’s roles.');
      },
    });
  }

  openPicker(): void {
    this.pickerOpen.set(true);
    this.pickerSelection.set(new Set());
    this.pickerSearch.set('');
    this.pickerError.set('');
  }

  closePicker(): void {
    this.pickerOpen.set(false);
  }

  togglePickerItem(id: string): void {
    this.pickerSelection.update(current => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  addRoles(): void {
    const teamId = this.teamId();
    const roleIds = [...this.pickerSelection()];
    if (!teamId || !roleIds.length || this.pickerSaving()) return;
    this.pickerSaving.set(true);
    this.pickerError.set('');
    forkJoin(roleIds.map(roleId =>
      this.api.post<TeamRoleItem>(`/api/v1/admin/security/teams/${teamId}/roles`, { role_id: roleId }),
    )).subscribe({
      next: () => {
        this.pickerSaving.set(false);
        this.closePicker();
        this.load(teamId);
      },
      error: (e: ApiError) => {
        this.pickerSaving.set(false);
        this.pickerError.set(e.message || 'Could not add the selected roles.');
      },
    });
  }

  removeRole(role: TeamRoleItem): void {
    const teamId = this.teamId();
    if (!teamId || this.removingId()) return;
    this.removingId.set(role.id);
    this.error.set('');
    this.api.delete(`/api/v1/admin/security/teams/${teamId}/roles/${role.role_id}`).subscribe({
      next: () => {
        this.removingId.set(null);
        this.load(teamId);
      },
      error: (e: ApiError) => {
        this.removingId.set(null);
        this.error.set(e.message || 'Could not remove the role.');
      },
    });
  }
}
