import { Injectable, computed, signal } from '@angular/core';

/**
 * `GET /api/v1/apps` — mirrors `attome-api`'s self-service `AvailableApp`
 * (`crates/engine/attome-api/src/app_admin.rs`). Moved here from
 * `app-switcher.component.ts` (R-10, M26-dashboard-remediation) so a second
 * consumer (`DashboardComponent`'s home-page routing) can read the caller's
 * currently-selected app without importing a component.
 */
export interface AvailableApp {
  id: string;
  name: string;
  icon: string;
  sidebar_root_ref: string | null;
  default_dashboard_ref: string | null;
  /** Entity logicalnames — a pure client-side sidebar filter, see
   * `AppSwitcherComponent`'s own doc comment and D-467. */
  entities: string[];
}

export const APP_SELECTION_STORAGE_KEY = 'attome:selected-app';

/**
 * The single owner of "which app is currently selected" — both the
 * persisted selection (`localStorage`, `APP_SELECTION_STORAGE_KEY`) and the
 * in-memory app list `AppSwitcherComponent` fetches once from
 * `GET /api/v1/apps` on shell boot. `AppSwitcherComponent` is still the only
 * thing that calls that endpoint (`setApps`) and the only thing that changes
 * the selection (`select`) — this service exists so a second consumer
 * (`DashboardComponent`'s home-page routing, R-10) can read the resolved
 * selection reactively without re-fetching the app list or re-reading
 * `localStorage` itself (coding-guidelines.md's "do not duplicate the
 * storage read").
 */
@Injectable({ providedIn: 'root' })
export class AppContextService {
  private readonly apps = signal<AvailableApp[]>([]);
  private readonly selectedId = signal<string | null>(this.readStoredSelection());

  /** `false` until `setApps` has been called once (success or failure) —
   * lets a consumer that needs the *resolved* selection (not just whatever
   * `localStorage` happened to hold before the app list arrived) wait for
   * that first load rather than momentarily seeing "no app selected". */
  readonly loaded = signal(false);

  readonly selectedApp = computed(() =>
    this.apps().find(a => a.id === this.selectedId()) ?? null);

  /** Called once by `AppSwitcherComponent` after `GET /api/v1/apps`
   * resolves — the one place that owns the fetch. */
  setApps(apps: AvailableApp[]): void {
    this.apps.set(apps);
    this.loaded.set(true);
  }

  select(id: string | null): void {
    this.selectedId.set(id);
    this.storeSelection(id);
  }

  private readStoredSelection(): string | null {
    try {
      return localStorage.getItem(APP_SELECTION_STORAGE_KEY);
    } catch {
      return null;
    }
  }

  private storeSelection(id: string | null): void {
    try {
      if (id) localStorage.setItem(APP_SELECTION_STORAGE_KEY, id);
      else localStorage.removeItem(APP_SELECTION_STORAGE_KEY);
    } catch {
      // Private browsing / storage disabled — the selection just doesn't
      // survive a reload, same graceful-degradation posture every other
      // localStorage user in this workspace takes.
    }
  }
}
