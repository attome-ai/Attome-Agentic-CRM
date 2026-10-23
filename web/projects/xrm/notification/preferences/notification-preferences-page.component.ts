import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import {
  NotificationPreferences, NotificationPreferencesService, PREFERENCE_CHANNELS, PreferenceChannel,
} from './notification-preferences.service';

/** One category row of the toggle table. */
interface CategoryRow {
  key: string;
  label: string;
  /** `true` = delivered on that channel (no row, or an enabled row). */
  channels: Record<PreferenceChannel, boolean>;
}

/** M15-T2/T3: how low-priority notifications are delivered. */
export const DIGEST_MODES = ['off', 'hourly', 'daily'] as const;
export type DigestMode = typeof DIGEST_MODES[number];

/** The `notification.quiet_hours` value for two `HH:MM` inputs: both or none. */
export function quietHoursValue(start: string, end: string): { start: string; end: string } | Record<string, never> {
  const valid = (t: string) => /^([01][0-9]|2[0-3]):[0-5][0-9]$/.test(t);
  return valid(start) && valid(end) && start !== end ? { start, end } : {};
}

/** Platform event categories that have a translated label. */
const EVENT_LABELS: Record<string, string> = {
  reminder: 'notificationPrefs.category.reminder',
};

/**
 * "Notifications" (U5, D-602) — the signed-in user's per-category channel
 * toggles, reached from the profile menu. Each toggle saves at once with
 * the row's `row_version`; a 409 reloads the table and says why.
 *
 * Mute-only by design (B-R5): account-security mail and templates an
 * administrator marked mandatory are never listed, because no preference
 * can stop them.
 */
@Component({
  selector: 'attome-notification-preferences-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', './notification-preferences-page.component.css'],
  templateUrl: './notification-preferences-page.component.html',
})
export class NotificationPreferencesPageComponent implements OnInit {
  private readonly svc  = inject(NotificationPreferencesService);
  private readonly lang = inject(LangService);
  private readonly api  = inject(ApiService);

  readonly digestModes = DIGEST_MODES;
  /** M15-T3: the delivery settings, from `/api/v1/settings/me`. */
  digest: DigestMode = 'off';
  quietStart = '';
  quietEnd = '';
  readonly savingDelivery = signal(false);

  readonly channels = PREFERENCE_CHANNELS;

  readonly doc       = signal<NotificationPreferences | null>(null);
  readonly loading   = signal(true);
  readonly error     = signal<string | null>(null);
  readonly notice    = signal<string | null>(null);
  /** `category:channel` of the toggle whose save is in flight. */
  readonly busyKey   = signal<string | null>(null);

  readonly rows = computed<CategoryRow[]>(() => {
    const doc = this.doc();
    if (!doc) return [];
    return doc.categories.map(key => {
      const channels = {} as Record<PreferenceChannel, boolean>;
      for (const channel of PREFERENCE_CHANNELS) {
        const stored = doc.items.find(i => i.category === key && i.channel === channel);
        channels[channel] = stored ? stored.enabled : true;
      }
      return { key, label: this.labelFor(key), channels };
    });
  });

  ngOnInit(): void { this.load(); this.loadDelivery(); }

  loadDelivery(): void {
    this.api.get<{ items: { key: string; value: unknown }[] }>('/api/v1/settings/me').subscribe({
      next: doc => {
        for (const item of doc.items) {
          if (item.key === 'notification.digest' && DIGEST_MODES.includes(item.value as DigestMode)) {
            this.digest = item.value as DigestMode;
          }
          if (item.key === 'notification.quiet_hours' && item.value && typeof item.value === 'object') {
            const v = item.value as { start?: string; end?: string };
            this.quietStart = v.start ?? '';
            this.quietEnd = v.end ?? '';
          }
        }
      },
      error: (e: ApiError) => this.error.set(this.errorText(e)),
    });
  }

  /** Saves the digest choice and the quiet hours (empty times clear them). */
  saveDelivery(): void {
    this.savingDelivery.set(true);
    this.notice.set(null);
    this.error.set(null);
    const quiet = quietHoursValue(this.quietStart, this.quietEnd);
    this.api.put<unknown>('/api/v1/settings/me/notification.digest', { value: this.digest }).subscribe({
      next: () => this.api.put<unknown>('/api/v1/settings/me/notification.quiet_hours', { value: quiet }).subscribe({
        next: () => {
          this.savingDelivery.set(false);
          this.notice.set(this.lang.translate('notificationPrefs.delivery.saved'));
        },
        error: (e: ApiError) => { this.savingDelivery.set(false); this.error.set(this.errorText(e)); },
      }),
      error: (e: ApiError) => { this.savingDelivery.set(false); this.error.set(this.errorText(e)); },
    });
  }

  /** `keepError`: a reload after a conflict keeps the message that explains it. */
  load(keepError = false): void {
    this.loading.set(true);
    if (!keepError) this.error.set(null);
    this.svc.load().subscribe({
      next: doc => { this.doc.set(doc); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.errorText(e)); this.loading.set(false); },
    });
  }

  toggle(row: CategoryRow, channel: PreferenceChannel): void {
    const key = `${row.key}:${channel}`;
    if (this.busyKey()) return;
    const stored = this.doc()?.items.find(i => i.category === row.key && i.channel === channel);
    const enabled = !row.channels[channel];
    this.busyKey.set(key);
    this.notice.set(null);
    this.error.set(null);
    this.svc.save([{ category: row.key, channel, enabled, row_version: stored?.row_version ?? null }]).subscribe({
      next: doc => {
        this.doc.set(doc);
        this.busyKey.set(null);
        this.notice.set(this.lang.translate(
          enabled ? 'notificationPrefs.turnedOn' : 'notificationPrefs.turnedOff',
          { category: row.label, channel: this.lang.translate(`notificationPrefs.channel.${channel}`) },
        ));
      },
      error: (e: ApiError) => {
        this.busyKey.set(null);
        this.error.set(this.errorText(e));
        if (e.kind === 'conflict' || e.kind === 'version_conflict') this.load(true);
      },
    });
  }

  private labelFor(key: string): string {
    const labelKey = EVENT_LABELS[key];
    return labelKey ? this.lang.translate(labelKey) : key;
  }

  private errorText(e: ApiError): string {
    switch (e.kind) {
      case 'conflict':
      case 'version_conflict': return this.lang.translate('notificationPrefs.error.conflict');
      default:                 return e.message || this.lang.translate('notificationPrefs.error.failed');
    }
  }
}
