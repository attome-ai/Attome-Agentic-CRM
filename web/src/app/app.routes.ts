import { inject } from '@angular/core';
import { CanActivateFn, Router, Routes } from '@angular/router';
import { map } from 'rxjs';
import { AuthService, authGuard } from '@attome/base';

// Same rule as `authGuard`: wait for the one session bootstrap before
// branching, so /xrm never sends a logged-in user to the login page merely
// because the session round trip hadn't landed yet.
const xrmEntryGuard: CanActivateFn = () => {
  const auth   = inject(AuthService);
  const router = inject(Router);
  return auth.sessionReady().pipe(
    map(() => router.createUrlTree(auth.isLoggedIn() ? ['/xrm/dashboard'] : ['/xrm/login'])),
  );
};

export const routes: Routes = [
  {
    path: '',
    pathMatch: 'full',
    redirectTo: 'xrm',
  },
  {
    // The guard always answers with a redirect (dashboard or login), so
    // nothing renders here.
    path: 'xrm',
    pathMatch: 'full',
    canActivate: [xrmEntryGuard],
    children: [],
  },
  {
    path: 'xrm/login',
    loadComponent: () => import('./pages/login/login.component').then(m => m.LoginComponent),
  },
  {
    path: 'register',
    loadComponent: () => import('./pages/register/register.component').then(m => m.RegisterComponent),
  },
  {
    // P-account-lifecycle — these three ship from `@attome/base/account`, their
    // own entry point (NGB-5.1a, D-760), so they load per route instead of
    // sitting in `main` (D-311 item 1: a dynamic import of the root barrel
    // could not tree-shake, a secondary entry point can).
    path: 'forgot-password',
    loadComponent: () => import('@attome/base/account').then(m => m.ForgotPasswordPageComponent),
    data: { backRoute: '/xrm/login' },
  },
  {
    path: 'reset-password',
    loadComponent: () => import('@attome/base/account').then(m => m.ResetPasswordPageComponent),
    data: { backRoute: '/xrm/login', successRoute: '/xrm/login' },
  },
  {
    path: 'verify-email',
    loadComponent: () => import('@attome/base/account').then(m => m.VerifyEmailPageComponent),
    data: { backRoute: '/xrm/login', successRoute: '/xrm/login' },
  },
  {
    // P-federation-linking-policy §4.3(a) — path is not a free choice, the
    // backend hardcodes its post-linking redirect to exactly this route
    // (`crates/server/src/auth.rs`'s `identity_link_oidc_callback`).
    path: 'settings/security',
    canActivate: [authGuard],
    loadComponent: () => import('./pages/security-settings/security-settings.component').then(m => m.SecuritySettingsComponent),
  },
  {
    // Bundle-size follow-up: split into its own lazy-loaded routes file
    // (xrm-shell.routes.ts) specifically so `provideXrmEntityForms()` can be
    // a route-scoped provider instead of living in the root ApplicationConfig
    // — see that file's header comment for why.
    path: 'xrm',
    loadChildren: () => import('./xrm-shell.routes').then(m => m.xrmShellRoutes),
    // AA12-T1: the signed-in app is where the sign-in page leads.
    data: { preload: true },
  },
  {
    // Solution 7 Phase 2 (design §10.5): the post-apply notification's route
    // is `/admin/release-reports/{id}` (`attome_api::changeset::report::
    // report_route`), and the notification bell navigates to it verbatim.
    // The page lives under `/xrm/admin`; without these redirects the link
    // would fall through to the Content Management catch-all below.
    path: 'admin/release-reports',
    pathMatch: 'full',
    redirectTo: '/xrm/admin/release-reports',
  },
  {
    path: 'admin/release-reports/:id',
    redirectTo: '/xrm/admin/release-reports/:id',
  },
  {
    // F5-T15: the hosted payment page a payment link opens. Public, no
    // session; ahead of the Content Management catch-all below.
    path: 'pay/:token',
    loadComponent: () => import('./pages/pay/pay-page.component').then(m => m.PayPageComponent),
  },
  {
    // E26-T2: the contact's preference page from a signed email link.
    // Public, no session; ahead of the Content Management catch-all below.
    path: 'preferences',
    loadComponent: () => import('@attome/xrm/portal/preferences').then(m => m.PreferencesComponent),
  },
  {
    // Work Intake self-service portal (M70, D-423) — public offering
    // browsing + request-status-by-token lookup, no session/authGuard. Must
    // sit ahead of the Content Management catch-all below, or a real deep
    // link to `/portal` would instead resolve as an (almost certainly
    // 404ing) published-page lookup.
    path: 'portal',
    loadComponent: () => import('@attome/xrm/service/portal').then(m => m.PortalPageComponent),
  },
  {
    // Content Management (D-NNN) — lowest-priority catch-all. A published
    // page's custom URL (e.g. `/guide/templates`) is resolved here against
    // the public, anonymous `GET /api/v1/content/view` endpoint; the
    // component itself renders a real "Page not found" message when that
    // 404s, replacing the previous silent `redirectTo: ''`.
    path: '**',
    loadComponent: () => import('@attome/xrm/content/view').then(m => m.ContentPageViewComponent),
  },
];
