/*
 * @attome/base/native — what a phone can do (B17-T2): the camera, the
 * position, links shared into the app, calls and WhatsApp, through the
 * Capacitor shell's native bridge when the page runs inside it and the web's
 * own way otherwise.
 */
export { NativeService, phoneDigits, whatsAppLink } from './native.service';
export type { Photo, Position, SharedItem } from './native.service';
// B17-T5 — biometric unlock after the lock timeout, the wipe check, the privacy screen.
export { DEFAULT_LOCK_MS, DEVICE_ID_KEY, DeviceSecurityService, mustUnlock, needsPrivacy } from './device-security.service';
// B17-T8 — push: the token registered with J12, taps opened by route, Approve decided.
export { PUSH_SUBSCRIPTION_KEY, PushService, approvalIdOf, isAppRoute } from './push.service';
// B17-T9 — the MDM's managed configuration: deployment address, copy block, lock timeout.
export { ManagedConfigService, managedAddress } from './managed-config.service';
export type { ManagedConfig } from './managed-config.service';

