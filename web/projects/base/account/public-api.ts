/*
 * @attome/base/account — the account-lifecycle pages (NGB-5.1a, D-760). Their
 * own entry point so a host lazy-loads them per route instead of carrying them
 * in `main` (D-311 item 1). Shared services come from `@attome/base` by
 * package name; the primary entry point never imports this one.
 */
export { ForgotPasswordPageComponent } from './forgot-password-page/forgot-password-page.component';
export { ResetPasswordPageComponent }  from './reset-password-page/reset-password-page.component';
export { VerifyEmailPageComponent }    from './verify-email-page/verify-email-page.component';
