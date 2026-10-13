// Self-service pages every logged-in user reaches regardless of role (P-frontend-
// hardening step 5) — kept out of `@attome/xrm/security`'s admin-only grant
// management so viewing your own access/MFA settings doesn't pull in the
// role/team/record-share administration UI. Neither component depends on
// SecurityAdminService (confirmed: both only use @attome/base's Api/AuthService).
export { MyAccessComponent }            from './my-access/my-access.component';
export { MfaSettingsComponent }         from './mfa-settings/mfa-settings.component';
