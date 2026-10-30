// @attome/xrm/portal/portal-shell — G12-T1: a web portal for its signed-in
// users at `/p/:keyword`, its pages drawn by the page runtime through the
// portal's own API. Lazy-loaded by the host's `/p` route.
import type { Routes } from '@angular/router';

import {
  PortalConsentComponent, PortalHereComponent, PortalLoginComponent, PortalPageHostComponent, PortalProfileComponent,
} from './portal-pages.component';
import { PortalPrivacyComponent } from './portal-privacy.component';
import { PortalShellComponent } from './portal-shell.component';

export { PortalShellComponent, navigation } from './portal-shell.component';
export {
  PortalConsentComponent, PortalHereComponent, PortalLoginComponent, PortalPageHostComponent, PortalProfileComponent, replyOf,
} from './portal-pages.component';
export type { ReplyTarget } from './portal-pages.component';
export { PortalCreateFormComponent, createOf, formFields, valueFor } from './portal-create-form.component';
export type { CreateTarget, PortalField } from './portal-create-form.component';
export { PRIVACY_REQUEST_TYPES, PortalPrivacyComponent } from './portal-privacy.component';
export type { PortalPrivacyRequest } from './portal-privacy.component';
export { PORTAL_ROWS, PortalPageData, PortalSiteService, portalFilters } from './portal-site.service';
export type { PortalConsent, PortalMe, PortalPage, PortalPageSummary } from './portal-site.service';

/** The routes under the host's `p`. */
export const PORTAL_SITE_ROUTES: Routes = [
  // A page's navigate target names the portal as `-` (it cannot know the keyword).
  { path: '-', children: [{ path: '**', component: PortalHereComponent }] },
  {
    path: ':keyword',
    component: PortalShellComponent,
    children: [
      { path: '', component: PortalPageHostComponent },
      { path: 'login', component: PortalLoginComponent },
      { path: 'profile', component: PortalProfileComponent },
      { path: 'consent', component: PortalConsentComponent },
      { path: 'privacy', component: PortalPrivacyComponent },
      { path: ':page', component: PortalPageHostComponent },
      { path: ':page/:id', component: PortalPageHostComponent },
    ],
  },
];
