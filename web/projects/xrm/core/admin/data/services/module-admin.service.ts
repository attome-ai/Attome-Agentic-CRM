import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

export interface RuntimeModule {
  name: string;
  enabled: boolean;
  /** Always true since D-778: no licence is checked. */
  licensed: boolean;
  /** Y4-T5: its engine's version; absent when no engine owns the module. */
  version?: string | null;
  /** Y4-T5: the modules that must be on while this one is on. */
  depends_on?: string[];
  /** Y4-T5: people who changed its records in 30 days; absent when unknown. */
  active_users_30d?: number | null;
}

/** One sidebar area of an installed project (vertical), e.g. Game Ops → Bans. */
export interface ProjectArea {
  id: string;
  name: string;
  is_active: boolean;
  row_version: number;
}

/**
 * D-778: an installed project (vertical). Switching it or one of its areas off
 * only hides it from the sidebar and dashboard (the sidebar item's
 * `is_active`); its data and API stay reachable.
 */
export interface ProjectSection extends ProjectArea {
  areas: ProjectArea[];
}

export interface ModuleConfiguration {
  enabled: boolean;
  modules: RuntimeModule[];
  projects: ProjectSection[];
}

/**
 * Module Management's client. The route keeps its historical
 * `/api/v1/admin/license/…` path on the server; since D-778 it switches
 * modules on and off and checks no licence.
 */
@Injectable({ providedIn: 'root' })
export class ModuleAdminService {
  private readonly api = inject(ApiService);

  getModuleConfiguration(): Observable<ModuleConfiguration> {
    return this.api.get<ModuleConfiguration>('/api/v1/admin/license/modules');
  }

  updateModuleConfiguration(enabled: boolean, modules: string[]): Observable<ModuleConfiguration> {
    return this.api.put<ModuleConfiguration>('/api/v1/admin/license/modules', { enabled, modules });
  }
}
