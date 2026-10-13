import { inject } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { map } from 'rxjs';
import { AuthService } from './auth.service';
import { ATTOME_CONFIG } from './config';

/**
 * Waits for the one session bootstrap before deciding — D-129's invariant is
 * that no authorization decision is ever made from a client-side marker, nor
 * before the server has answered. The app initializer starts that bootstrap
 * at startup without blocking the first paint, so in the common case
 * `sessionReady()` has already resolved and replays synchronously: this
 * guard costs no extra round trip and no extra delay.
 */
export const authGuard: CanActivateFn = (route, state) => {
  const auth       = inject(AuthService);
  const router     = inject(Router);
  const config     = inject(ATTOME_CONFIG);
  const loginRoute = config.loginRoute ?? '/login';

  return auth.sessionReady().pipe(
    // Read the live signal, not the emitted value — a login after bootstrap
    // updates the former but not the latter (see `sessionReady`'s doc).
    map(() => auth.isLoggedIn() || router.createUrlTree([loginRoute], {
      queryParams: { returnUrl: state.url },
    })),
  );
};
