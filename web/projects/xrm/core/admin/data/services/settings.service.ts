import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

/** Mirrors `SettingScope` (`attome-core::setting_descriptor`, M02/D-412). */
export type SettingScope = 'user' | 'organization' | 'deployment';

/**
 * Mirrors `attome-api::settings_admin::SettingValueView` — one registered,
 * runtime-eligible setting plus its resolved effective value. `schema` is a
 * JSON Schema fragment (currently `type`/`enum`/`minimum`/`maximum`/
 * `minLength`/`maxLength`/`pattern` are the keywords the backend's own
 * validator understands — see `attome_core::setting_store`'s module doc).
 */
export interface SettingValueView {
  key:             string;
  description:     string;
  /** U10-T1: the admin console area (`general`, `security`, `features`, `ai`, `channels`). */
  area?:           string;
  /** U10-T1: the description in Arabic. */
  description_ar?: string | null;
  schema:          Record<string, unknown>;
  allowed_scopes:  SettingScope[];
  boot_time_only:  boolean;
  value:           unknown;
  /** Where `value` was resolved from: 'user' | 'organization' | 'deployment' | 'default'. */
  source:          string;
  updated_at:      string | null;
}

export interface SettingListResponse {
  items: SettingValueView[];
}

@Injectable({ providedIn: 'root' })
export class SettingsService {
  private readonly api = inject(ApiService);

  /** Admin overview — every runtime-eligible setting's deployment-scope
   * effective value (a deployment override if one exists, else its code
   * default). `boot_time_only` settings never appear here. */
  listAdminSettings(): Observable<SettingListResponse> {
    return this.api.get<SettingListResponse>('/api/v1/admin/settings');
  }

  /** Admin-only write, at an explicit scope. `scopeRef` is required for
   * `organization`/`user` scope and must be omitted for `deployment`. */
  putAdminSetting(
    key: string,
    scope: SettingScope,
    value: unknown,
    scopeRef?: string,
  ): Observable<SettingValueView> {
    return this.api.put<SettingValueView>(`/api/v1/admin/settings/${encodeURIComponent(key)}`, {
      scope,
      scope_ref: scopeRef ?? null,
      value,
    });
  }

  /** Every runtime-eligible setting that allows the `user` scope, resolved
   * for the calling user (their own override, else org, else deployment,
   * else the code default). */
  listMySettings(): Observable<SettingListResponse> {
    return this.api.get<SettingListResponse>('/api/v1/settings/me');
  }

  /** Sets the calling user's own override. */
  putMySetting(key: string, value: unknown): Observable<SettingValueView> {
    return this.api.put<SettingValueView>(`/api/v1/settings/me/${encodeURIComponent(key)}`, { value });
  }
}
