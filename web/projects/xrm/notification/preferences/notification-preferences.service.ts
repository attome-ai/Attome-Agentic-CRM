import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';
import type { ApiComponents } from '@attome/base';

type Schemas = ApiComponents['schemas'];

/** `GET/PUT /api/v1/me/notification-preferences` (200). */
export type NotificationPreferences = Schemas['NotificationPreferences'];
export type NotificationPreference = Schemas['NotificationPreference'];
export type NotificationPreferenceWrite = Schemas['NotificationPreferenceWrite'];

/** The channels the preferences page offers a toggle for. */
export const PREFERENCE_CHANNELS = ['in_app', 'email'] as const;
export type PreferenceChannel = (typeof PREFERENCE_CHANNELS)[number];

/**
 * The signed-in user's own notification preferences (U5, D-602). The server
 * keys every row by the session's user, so nothing here names a user.
 * Preferences can only mute: a channel with no row is on, and a template an
 * administrator marked mandatory is never listed.
 */
@Injectable({ providedIn: 'root' })
export class NotificationPreferencesService {
  private readonly api = inject(ApiService);

  load(): Observable<NotificationPreferences> {
    return this.api.get<NotificationPreferences>('/api/v1/me/notification-preferences');
  }

  save(items: NotificationPreferenceWrite[]): Observable<NotificationPreferences> {
    return this.api.put<NotificationPreferences>('/api/v1/me/notification-preferences', { items });
  }
}
