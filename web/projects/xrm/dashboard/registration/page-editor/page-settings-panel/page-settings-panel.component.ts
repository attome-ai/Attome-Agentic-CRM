import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityRecordResponse } from '@attome/xrm/core/entity';
import { RecordSharesComponent } from '@attome/xrm/core/security';

type PageSettingsTab = 'general' | 'parameters' | 'access';

/** `dashboard_page.settings` — a JSON-as-text column, the same
 * "structured-but-scalar" extension-field convention `attome_dashboard.settings`/
 * `dashboard_widget.query_params` already use (see
 * `attome-dashboard/src/decision_seed.rs`'s doc comment for the precedent). No
 * schema change needed for any of these — the column already exists and is
 * free-form. */
interface PageSettingsJson {
  description?: string;
  /** Minutes; 0 = off. */
  refresh_interval_minutes?: number;
  timezone?: string;
  text_color?: string;
  accent_color?: string;
  border_radius?: 'small' | 'medium' | 'large';
}

// `label` is a translation key, resolved with `| translate` in the template
// (same convention `LifecycleAction.label` uses in `dashboard-editor.component.ts`).
const REFRESH_INTERVAL_OPTIONS: { value: number; label: string }[] = [
  { value: 0, label: 'pageEditor.refreshOff' },
  { value: 1, label: 'pageEditor.refresh1Min' },
  { value: 5, label: 'pageEditor.refresh5Min' },
  { value: 15, label: 'pageEditor.refresh15Min' },
  { value: 30, label: 'pageEditor.refresh30Min' },
  { value: 60, label: 'pageEditor.refresh1Hour' },
];

const TIMEZONE_OPTIONS = [
  'UTC', 'America/New_York', 'America/Los_Angeles', 'Europe/London', 'Europe/Paris',
  'Asia/Dubai', 'Asia/Riyadh', 'Asia/Kolkata', 'Asia/Shanghai', 'Asia/Tokyo', 'Australia/Sydney',
];

const BORDER_RADIUS_OPTIONS: PageSettingsJson['border_radius'][] = ['small', 'medium', 'large'];
const BACKGROUND_KINDS = ['color', 'image', 'gradient'];
const PARAMETER_TYPES = ['text', 'number', 'date_range', 'choice', 'entity_lookup'];

export interface ParameterFieldChange {
  id:    string;
  field: string;
  value: unknown;
}

function parsePageSettings(raw: unknown): PageSettingsJson {
  if (typeof raw !== 'string' || !raw.trim()) return {};
  try {
    return JSON.parse(raw) as PageSettingsJson;
  } catch {
    return {};
  }
}

/**
 * General / Parameters / Access tabs for the page itself (shown when no
 * widget is selected). Signal inputs/outputs only, no service injection
 * (R-11): every field edit merges into a patch reported through `pagePatch`
 * (the plain fields directly, `settings` fields folded into the existing
 * JSON blob first) — `PageEditorComponent` owns applying it to the draft.
 * Parameter CRUD (`parameterAdd`/`parameterChange`/`parameterDelete`)
 * commits immediately rather than through the draft, same as it always has
 * — that decision belongs to `PageEditorComponent`'s doc comment, not here.
 */
@Component({
  selector:   'xrm-page-settings-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [TranslatePipe, RecordSharesComponent],
  styleUrls:  ['./page-settings-panel.component.css'],
  templateUrl: './page-settings-panel.component.html',
})
export class PageSettingsPanelComponent {
  readonly page       = input.required<EntityRecordResponse>();
  readonly parameters = input<EntityRecord[]>([]);

  readonly pagePatch        = output<Record<string, unknown>>();
  readonly parameterAdd     = output<void>();
  readonly parameterChange  = output<ParameterFieldChange>();
  readonly parameterDelete  = output<string>();

  readonly tab = signal<PageSettingsTab>('general');

  readonly refreshIntervalOptions = REFRESH_INTERVAL_OPTIONS;
  readonly timezoneOptions        = TIMEZONE_OPTIONS;
  readonly borderRadiusOptions    = BORDER_RADIUS_OPTIONS;
  readonly backgroundKinds        = BACKGROUND_KINDS;
  readonly parameterTypes         = PARAMETER_TYPES;

  readonly settings = computed<PageSettingsJson>(() => parsePageSettings(this.page().data['settings']));

  onField(field: string, value: unknown): void {
    this.pagePatch.emit({ [field]: value });
  }

  onSettingsField<K extends keyof PageSettingsJson>(field: K, value: PageSettingsJson[K]): void {
    const merged: PageSettingsJson = { ...this.settings(), [field]: value };
    this.pagePatch.emit({ settings: JSON.stringify(merged) });
  }

  /** The `<select>`'s own `.value` is a plain `string` — this is the one
   * narrowing point back to `PageSettingsJson['border_radius']`'s union,
   * safe because `radiusSelect`'s `<option>`s are generated from
   * `borderRadiusOptions` (this same union) and nothing else populates it. */
  onBorderRadiusChange(value: string): void {
    this.onSettingsField('border_radius', value as PageSettingsJson['border_radius']);
  }

  onParameterField(id: string, field: string, value: unknown): void {
    this.parameterChange.emit({ id, field, value });
  }
}
