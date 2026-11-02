/*
 * @attome/base/native — what a phone can do (B17-T2): the camera, the
 * position, links shared into the app, calls and WhatsApp, through the
 * Capacitor shell's native bridge when the page runs inside it and the web's
 * own way otherwise.
 */
export { NativeService, phoneDigits, whatsAppLink } from './native.service';
export type { Photo, Position, SharedItem } from './native.service';
