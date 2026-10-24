import { inject } from '@angular/core';
import { CanActivateFn, Route, Router } from '@angular/router';
import { authGuard } from '@attome/base';

const NAME = /^[a-z][a-z0-9_]{0,62}$/;

/**
 * B16-T11: `/r/{entity}/{id}` (what a record's QR code carries) opens the
 * record's form. It runs after the sign-in guard, so an anonymous scan goes
 * to sign in first; the link names only the entity and the id, and the
 * record's own read check decides what the person sees.
 */
export const recordLinkGuard: CanActivateFn = route => {
  const router = inject(Router);
  const entity = route.paramMap.get('entity') ?? '';
  const id = route.paramMap.get('id') ?? '';
  if (!NAME.test(entity) || !id) return router.createUrlTree(['/']);
  // `entityFormRoute(entity)` in @attome/xrm/core/entity; spelled out so the
  // root routes do not import that entry point into the main bundle.
  return router.createUrlTree(['/xrm', 'entity', entity, 'form'], { queryParams: { id } });
};

/** The host app's route for record links. */
export const RECORD_LINK_ROUTE: Route = {
  path: 'r/:entity/:id',
  canActivate: [authGuard, recordLinkGuard],
  children: [],
};
