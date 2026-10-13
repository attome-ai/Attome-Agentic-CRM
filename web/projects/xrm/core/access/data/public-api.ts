// Services only — no components (D-314), so any entry point can read the
// signed-in user's privileges without pulling the self-service access pages.
export { AccessService } from './access.service';
