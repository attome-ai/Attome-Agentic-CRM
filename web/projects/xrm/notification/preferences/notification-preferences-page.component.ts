import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
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
  imports: [TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', './notification-preferences-page.component.css'],
  templateUrl: './notification-preferences-page.component.html',
})
export class NotificationPreferencesPageComponent implements OnInit {
  private readonly svc  = inject(NotificationPreferencesService);
  private readonly lang = inject(LangService);

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

  ngOnInit(): void { this.load(); }

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
