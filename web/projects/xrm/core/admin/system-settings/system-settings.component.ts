import { ChangeDetectionStrategy, Component, computed, inject, signal, WritableSignal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { catchError, of } from 'rxjs';

import { SidebarPreferencesService, SidebarStyle } from '@attome/xrm/core/admin/data';
import { SettingsService, SettingValueView } from '@attome/xrm/core/admin/data';
import { LangService } from '@attome/base';

/** What kind of control `renderSetting` should show for one descriptor's
 * JSON Schema (`attome_core::setting_store`'s validated-keyword subset —
 * see that module's doc comment for exactly which are enforced). */
type SettingControlKind = 'boolean' | 'number' | 'select' | 'text';

interface SettingRow {
  view: SettingValueView;
  kind: SettingControlKind;
  /** Present only when `kind === 'select'` (schema `enum`). */
  options: string[] | null;
  /** Live-edited value, seeded from `view.value`. A plain field (not a
   * signal) — the row itself is held in a signal array, so replacing the
   * array element on save is what triggers change detection (OnPush). */
  draft: unknown;
  status: WritableSignal<'idle' | 'saving' | 'saved' | 'error'>;
  error: WritableSignal<string | null>;
}

function controlKindFor(schema: Record<string, unknown>): { kind: SettingControlKind; options: string[] | null } {
  const enumValues = schema['enum'];
  if (Array.isArray(enumValues) && enumValues.every(v => typeof v === 'string')) {
    return { kind: 'select', options: enumValues as string[] };
  }
  const type = schema['type'];
  if (type === 'boolean') return { kind: 'boolean', options: null };
  if (type === 'integer' || type === 'number') return { kind: 'number', options: null };
  return { kind: 'text', options: null };
}

function toRow(view: SettingValueView): SettingRow {
  const { kind, options } = controlKindFor(view.schema);
  return {
    view,
    kind,
    options,
    draft: view.value,
    status: signal('idle'),
    error: signal(null),
  };
}

@Component({
  selector: 'xrm-system-settings',
  standalone: true,
  imports: [FormsModule],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./system-settings.component.css'],
  templateUrl: './system-settings.component.html',
})
export class SystemSettingsComponent {
  readonly preferences = inject(SidebarPreferencesService);
  private readonly settingsApi = inject(SettingsService);
  private readonly lang = inject(LangService);

  /** U10-T1: a setting's description in the interface language. */
  describe(view: SettingValueView): string {
    return this.lang.current() === 'ar' && view.description_ar ? view.description_ar : view.description;
  }

  /** Every runtime-eligible setting the calling user may set for
   * themselves (`allowed_scopes` includes `user`) — `/api/v1/settings/me`. */
  readonly mySettings = signal<SettingRow[]>([]);
  /** Deployment-wide defaults — `/api/v1/admin/settings`. `null` while
   * loading; stays `null` (never an error banner) for a non-admin caller,
   * since a 403 here just means "no admin section to show", not a failure
   * of the page. */
  readonly deploymentSettings = signal<SettingRow[] | null>(null);
  readonly hasDeploymentSettings = computed(() => (this.deploymentSettings()?.length ?? 0) > 0);

  constructor() {
    this.settingsApi.listMySettings().subscribe(res => {
      this.mySettings.set(res.items.map(toRow));
    });
    this.settingsApi
      .listAdminSettings()
      .pipe(catchError(() => of(null)))
      .subscribe(res => {
        this.deploymentSettings.set(res ? res.items.map(toRow) : []);
      });
  }

  selectStyle(style: SidebarStyle): void {
    this.preferences.setStyle(style);
  }

  saveMine(row: SettingRow): void {
    row.status.set('saving');
    row.error.set(null);
    this.settingsApi.putMySetting(row.view.key, row.draft).subscribe({
      next: view => {
        row.view = view;
        row.draft = view.value;
        row.status.set('saved');
        setTimeout(() => row.status.set('idle'), 1500);
      },
      error: err => {
        row.status.set('error');
        row.error.set(err?.error?.message ?? 'Could not save this setting.');
      },
    });
  }

  saveDeploymentDefault(row: SettingRow): void {
    row.status.set('saving');
    row.error.set(null);
    this.settingsApi.putAdminSetting(row.view.key, 'deployment', row.draft).subscribe({
      next: view => {
        row.view = view;
        row.draft = view.value;
        row.status.set('saved');
        setTimeout(() => row.status.set('idle'), 1500);
      },
      error: err => {
        row.status.set('error');
        row.error.set(err?.error?.message ?? 'Could not save this setting.');
      },
    });
  }
}
