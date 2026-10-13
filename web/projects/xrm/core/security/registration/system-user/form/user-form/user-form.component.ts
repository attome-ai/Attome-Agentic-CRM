import {
  ChangeDetectionStrategy, Component, ElementRef, Injector, afterNextRender, computed, inject, signal,
} from '@angular/core';
import { ReactiveFormsModule, Validators, type AbstractControl, type FormGroup, type ValidationErrors } from '@angular/forms';
import { LangService, TranslatePipe, isValidTimeZone } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import {
  ImageUploadComponent, RECORD_TAB_IDS, RelatedGridComponent, TagsPanelComponent,
  XrmBaseFormComponent, EngineFormBase, XrmTabDirective, recordTabDefs,
} from '@attome/xrm/core/entity';
import type { EntityRecordResponse, XrmFormTabDef } from '@attome/xrm/core/entity';
import { UserSecurityPanelComponent } from '../user-security-panel/user-security-panel.component';

/** Blank is allowed (it means "use the browser's zone"); anything else must be a zone `Intl` accepts. */
function timeZoneValidator(control: AbstractControl): ValidationErrors | null {
  const v = typeof control.value === 'string' ? control.value.trim() : '';
  return v === '' || isValidTimeZone(v) ? null : { timezone: true };
}

/** Every IANA zone this browser knows, for the timezone field's suggestions. */
function supportedTimeZones(): string[] {
  const intl = Intl as unknown as { supportedValuesOf?: (key: string) => string[] };
  try {
    return intl.supportedValuesOf?.('timeZone') ?? [];
  } catch {
    return [];
  }
}

function text(v: unknown): string | null {
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : null;
}

/**
 * The system user form. Details (the record's own fields), Access (roles,
 * sign-in, teams, direct privileges), Settings (activate or deactivate the
 * account), then the platform record tabs. The identity header shows the
 * user's name and account status from the *saved* record, so it does not
 * flicker while the operator types.
 */
@Component({
  selector: 'xrm-user-form',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [
    ReactiveFormsModule, TranslatePipe, XrmBaseFormComponent, XrmTabDirective, ImageUploadComponent,
    RelatedGridComponent, TagsPanelComponent, UserSecurityPanelComponent,
  ],
  styleUrls: ['../../../../../../styles/xrm-form.css', './user-form.component.css'],
  templateUrl: './user-form.component.html',
})
export class UserFormComponent extends EngineFormBase {
  private readonly lang    = inject(LangService);
  private readonly host    = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly injector = inject(Injector);

  /** `last_login` from the loaded record — read-only, shown on the Access tab. */
  readonly lastLogin = signal<string | null>(null);
  readonly savedName  = signal<string | null>(null);
  readonly savedEmail = signal<string | null>(null);
  /** NULL is live on this table; only an explicit `false` is deactivated. */
  readonly accountActive = signal(true);
  readonly timeZones = supportedTimeZones();

  readonly displayName = computed(() => this.savedName() ?? this.savedEmail());

  // Labels are catalog keys; the template translates them.
  protected override defineTabs(): XrmFormTabDef[] {
    // The base form prints labels as given, so the catalog keys resolve here.
    const t = (key: string) => this.lang.translate(key);
    return [
      { id: 'details', label: t('userForm.tabs.details'), icon: 'las la-user' },
      { id: 'access',  label: t('userForm.tabs.access'),  icon: 'las la-shield-alt' },
      // Activate / deactivate the account.
      { id: 'settings', label: t('userForm.tabs.settings'), icon: 'las la-cog' },
      // D-773: the platform record tabs (they replace Activity and Files).
      // Tags already sit at the bottom of Details, so that tab is left out.
      ...recordTabDefs(this.name(), t, RECORD_TAB_IDS.filter(id => id !== 'tags')),
    ];
  }

  protected override buildFormGroup(schema: EntitySchema): FormGroup {
    const fg = super.buildFormGroup(schema);
    fg.get('email')?.addValidators(Validators.email);
    fg.get('timezone')?.addValidators(timeZoneValidator);
    return fg;
  }

  protected override onRecordLoaded(record: EntityRecordResponse): void {
    const d = record.data;
    this.lastLogin.set(text(d['last_login']));
    this.savedName.set(text(d['user_name']));
    this.savedEmail.set(text(d['email']));
    this.accountActive.set(d['is_active'] !== false);
  }

  /**
   * Every editable field lives on Details, but Save sits in the header and is
   * reachable from any tab. An invalid save therefore brings Details forward
   * and focuses the first field that needs attention, instead of reporting
   * errors the operator cannot see.
   *
   * A deactivated account cannot be saved at all: the generic update only
   * matches `is_active = true` rows (entity_mutation.rs), so it would 404.
   */
  override save(): void {
    if (!this.accountActive()) return;
    const refused = this.canSave() && this.form().invalid;
    super.save();
    if (!refused) return;
    this.selectTab('details');
    afterNextRender(
      () => this.host.nativeElement.querySelector<HTMLElement>('#user-panel-details [aria-invalid="true"]')?.focus(),
      { injector: this.injector },
    );
  }

  /**
   * A presence choice's display text. The choices come from the schema, so a
   * value added there without a catalog entry falls back to the raw value.
   */
  statusLabel(value: string): string {
    const key = `userForm.statusChoice.${value}`;
    const translated = this.lang.translate(key);
    return translated === key ? value : translated;
  }

  /** True once the operator has touched `name` and it fails `error`. */
  invalid(name: string, error?: string): boolean {
    const c = this.form().get(name);
    if (!c || !c.touched || c.valid) return false;
    return error ? c.hasError(error) : true;
  }
}
