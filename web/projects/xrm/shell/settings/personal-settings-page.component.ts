import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { PERSONAL_KEYS, PersonalKey, PersonalSettingsService } from './personal-settings.service';

/** How each setting is edited. */
type Control =
  | { kind: 'choice'; options: string[] }
  | { kind: 'text'; placeholder: string }
  | { kind: 'toggle' };

const CONTROLS: Record<PersonalKey, Control> = {
  'core.locale':         { kind: 'choice', options: ['en-US', 'ar-SA'] },
  'core.time_zone':      { kind: 'text', placeholder: 'Asia/Riyadh' },
  'core.calendar':       { kind: 'choice', options: ['gregorian', 'hijri', 'both'] },
  'core.digits':         { kind: 'choice', options: ['latn', 'arab'] },
  'core.date_format':    { kind: 'choice', options: ['dmy', 'mdy', 'ymd'] },
  'core.start_page':     { kind: 'text', placeholder: '/xrm/dashboard' },
  'core.theme':          { kind: 'choice', options: ['auto', 'light', 'dark'] },
  'core.text_size':      { kind: 'choice', options: ['normal', 'large'] },
  'core.reduced_motion': { kind: 'toggle' },
};

/** The catalogue key of a setting's label: `core.time_zone` -> `settingsPage.time_zone`. */
export function labelKey(key: string): string {
  return `settingsPage.${key.replace(/^core\./, '')}`;
}

/** The catalogue key of one choice: `settingsPage.option.hijri`. */
export function optionKey(option: string): string {
  return `settingsPage.option.${option.replace(/[^a-z0-9]/gi, '_')}`;
}

/**
 * "Settings" (B11-T2): the signed-in person's language, time zone, calendar,
 * digits, date order, start page, theme, text size and motion. Each change
 * saves at once and applies without a reload; a value set by the
 * organization or deployment is shown as such until the person overrides it.
 */
@Component({
  selector: 'xrm-personal-settings-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', './personal-settings-page.component.css'],
  templateUrl: './personal-settings-page.component.html',
})
export class PersonalSettingsPageComponent implements OnInit {
  protected readonly svc = inject(PersonalSettingsService);
  private readonly lang = inject(LangService);

  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly savedKey = signal<string | null>(null);
  readonly busyKey = signal<string | null>(null);

  readonly rows = computed(() => PERSONAL_KEYS.map(key => {
    const setting = this.svc.byKey().get(key);
    return {
      key,
      label: labelKey(key),
      control: CONTROLS[key],
      value: setting?.value,
      source: setting?.source ?? 'default',
    };
  }));

  readonly labelKey = labelKey;
  readonly optionKey = optionKey;

  ngOnInit(): void {
    this.svc.load().subscribe({
      next: () => this.loading.set(false),
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
  }

  save(key: PersonalKey, value: unknown): void {
    if (this.busyKey()) return;
    this.busyKey.set(key);
    this.error.set(null);
    this.svc.save(key, value).subscribe({
      next: () => { this.busyKey.set(null); this.savedKey.set(key); },
      error: (e: ApiError) => {
        this.busyKey.set(null);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  saveText(key: PersonalKey, event: Event): void {
    const value = (event.target as HTMLInputElement).value.trim();
    if (value) this.save(key, value);
  }
}
