import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { ApiService, LangService, TranslatePipe } from '@attome/base';

/** One channel's state: `true` granted, `false` withdrawn, `null` never asked. */
export interface ChannelState {
  channel: string;
  granted: boolean | null;
}

/** One purpose and its channels (`GET /api/v1/consents/preferences`). */
export interface PurposePreferences {
  key: string;
  description: string | null;
  channels: ChannelState[];
}

export interface Preferences {
  purposes: PurposePreferences[];
}

/** One change sent on save. */
export interface PreferenceChange {
  purpose_key: string;
  channel: string;
  grant: boolean;
}

/** Channels with their own label; any other shows its code. */
const KNOWN_CHANNELS = new Set(['any', 'email', 'sms', 'whatsapp', 'phone', 'ads']);

type Stage = 'loading' | 'ready' | 'saving' | 'saved' | 'invalid' | 'failed';

/**
 * The changes between what the server holds and what the page shows: every
 * box whose state differs, a never-asked box counting as off. Pure.
 */
export function toggledPreferences(
  stored: Preferences,
  shown: Record<string, boolean>,
): PreferenceChange[] {
  const out: PreferenceChange[] = [];
  for (const purpose of stored.purposes) {
    for (const c of purpose.channels) {
      const key = `${purpose.key}|${c.channel}`;
      if (!(key in shown)) continue;
      const before = c.granted === true;
      if (shown[key] !== before) {
        out.push({ purpose_key: purpose.key, channel: c.channel, grant: shown[key] });
      }
    }
  }
  return out;
}

/**
 * E26-T2: the public preference page a contact reaches from the signed link
 * in an email (`/preferences?token=…`, E26-T1). It lists what they may be
 * contacted about and on which channels, and saves only what they changed.
 * No session: the token is the authority, and an expired or altered one
 * shows a message rather than anyone's data. Both languages, with a toggle,
 * and logical CSS only.
 */
@Component({
  selector: 'xrm-portal-preferences',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <main class="pp" [attr.dir]="dir()" [attr.lang]="lang.current()">
      <header class="pp-head">
        <h1>{{ 'consentPreferences.title' | translate }}</h1>
        <button type="button" class="pp-lang" (click)="toggleLanguage()" data-testid="pref-lang">
          {{ 'consentPreferences.otherLanguage' | translate }}
        </button>
      </header>
      @switch (stage()) {
        @case ('loading') {
          <p role="status">{{ 'consentPreferences.loading' | translate }}</p>
        }
        @case ('invalid') {
          <p role="alert" data-testid="pref-invalid">{{ 'consentPreferences.invalidLink' | translate }}</p>
        }
        @case ('failed') {
          <p role="alert" data-testid="pref-failed">{{ 'consentPreferences.failed' | translate }}</p>
        }
        @default {
          <p class="pp-intro">{{ 'consentPreferences.intro' | translate }}</p>
          @if (purposes().length === 0) {
            <p data-testid="pref-empty">{{ 'consentPreferences.empty' | translate }}</p>
          }
          @for (p of purposes(); track p.key) {
            <fieldset class="pp-purpose" data-testid="pref-purpose">
              <legend>{{ p.description || p.key }}</legend>
              @for (c of p.channels; track c.channel) {
                <label class="pp-channel">
                  <input type="checkbox" [checked]="isOn(p.key, c.channel)"
                         (change)="set(p.key, c.channel, $any($event.target).checked)"
                         [attr.data-testid]="'pref-' + p.key + '-' + c.channel" />
                  {{ channelLabel(c.channel) }}
                </label>
              }
            </fieldset>
          }
          <div class="pp-actions">
            <button type="button" class="pp-save" [disabled]="stage() === 'saving' || changes().length === 0"
                    (click)="save()" data-testid="pref-save">
              {{ (stage() === 'saving' ? 'consentPreferences.saving' : 'consentPreferences.save') | translate }}
            </button>
            @if (stage() === 'saved') {
              <span role="status" data-testid="pref-saved">{{ 'consentPreferences.saved' | translate }}</span>
            }
          </div>
        }
      }
    </main>
  `,
  styles: [`
    .pp { max-inline-size: 640px; margin-inline: auto; padding-block: 32px; padding-inline: 16px;
          display: grid; gap: 16px; color: var(--color-text-primary); }
    .pp-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
    .pp-head h1 { margin: 0; font-size: 22px; }
    .pp-lang { background: none; border: none; color: var(--color-accent); cursor: pointer; }
    .pp-intro { margin: 0; color: var(--color-text-secondary); }
    .pp-purpose { border: 1px solid var(--color-border); border-radius: 8px;
                  padding-block: 12px; padding-inline: 16px; display: grid; gap: 8px; }
    .pp-purpose legend { font-weight: 600; padding-inline: 4px; }
    .pp-channel { display: flex; align-items: center; gap: 8px; }
    .pp-actions { display: flex; align-items: center; gap: 12px; }
    .pp-save { padding-block: 10px; padding-inline: 20px; border: none; border-radius: 8px;
               background: var(--color-accent); color: var(--color-bg); font-weight: 700; cursor: pointer; }
    .pp-save:disabled { opacity: .5; cursor: not-allowed; }
  `],
})
export class PreferencesComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly route = inject(ActivatedRoute);
  protected readonly lang = inject(LangService);

  readonly stage = signal<Stage>('loading');
  private readonly stored = signal<Preferences>({ purposes: [] });
  /** What each box shows, by `purpose|channel`. */
  private readonly shown = signal<Record<string, boolean>>({});
  private token = '';

  readonly purposes = computed(() => this.stored().purposes);
  readonly changes = computed(() => toggledPreferences(this.stored(), this.shown()));
  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));

  ngOnInit(): void {
    this.token = this.route.snapshot.queryParamMap.get('token') ?? '';
    if (!this.token) {
      this.stage.set('invalid');
      return;
    }
    this.api.get<Preferences>('/api/v1/consents/preferences', { token: this.token }).subscribe({
      next: prefs => this.load(prefs),
      error: (e: { kind?: string }) =>
        this.stage.set(e?.kind === 'not_found' || e?.kind === 'validation_error' ? 'invalid' : 'failed'),
    });
  }

  isOn(purpose: string, channel: string): boolean {
    return this.shown()[`${purpose}|${channel}`] === true;
  }

  set(purpose: string, channel: string, on: boolean): void {
    this.shown.update(s => ({ ...s, [`${purpose}|${channel}`]: on }));
    if (this.stage() === 'saved') this.stage.set('ready');
  }

  channelLabel(channel: string): string {
    return KNOWN_CHANNELS.has(channel)
      ? this.lang.translate(`consentPreferences.channel.${channel}`)
      : channel;
  }

  save(): void {
    const changes = this.changes();
    if (changes.length === 0) return;
    this.stage.set('saving');
    this.api.post<Preferences>('/api/v1/consents/preferences', { token: this.token, changes }).subscribe({
      next: prefs => {
        this.load(prefs);
        this.stage.set('saved');
      },
      error: (e: { kind?: string }) =>
        this.stage.set(e?.kind === 'not_found' || e?.kind === 'validation_error' ? 'invalid' : 'failed'),
    });
  }

  toggleLanguage(): void {
    void this.lang.toggle();
  }

  private load(prefs: Preferences): void {
    const shown: Record<string, boolean> = {};
    for (const p of prefs.purposes) {
      for (const c of p.channels) shown[`${p.key}|${c.channel}`] = c.granted === true;
    }
    this.stored.set(prefs);
    this.shown.set(shown);
    this.stage.set('ready');
  }
}
