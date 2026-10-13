// New top-level entry (D-099-era `notification` module has real backend
// implementation — attome-notification crate — but had no dedicated Angular
// home until this form; `shell/notification-bell` stays where it is, it's
// app chrome, not entity CRUD).
export { NotificationTemplateFormComponent } from './notification-template/form/notification-template-form/notification-template-form.component';
export { registerNotificationEntityForms } from './provide-notification-entity-forms';
// U5 (D-602) — the signed-in user's own notification preferences page,
// reached from the profile menu.
export { NotificationPreferencesPageComponent } from './preferences/notification-preferences-page.component';
export { NotificationPreferencesService, PREFERENCE_CHANNELS } from './preferences/notification-preferences.service';
export type {
  NotificationPreferences, NotificationPreference, NotificationPreferenceWrite, PreferenceChannel,
} from './preferences/notification-preferences.service';
