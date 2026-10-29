/**
 * Q6-T2: the browser half of a passkey ceremony. The server sends the
 * WebAuthn options as JSON (binary fields base64url-encoded) and takes the
 * browser's `PublicKeyCredential.toJSON()` back. Browsers that lack the
 * JSON helpers (`parseCreationOptionsFromJSON`, `toJSON`) get the same
 * conversion done here.
 */

import { InjectionToken } from '@angular/core';

type Json = Record<string, unknown>;

function isRecord(value: unknown): value is Json {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** base64url (no padding) to bytes. */
export function fromBase64Url(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

/** Bytes to base64url without padding. */
export function toBase64Url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes = buffer instanceof ArrayBuffer
    ? new Uint8Array(buffer)
    : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Whether this browser can use passkeys at all. */
export function passkeysSupported(): boolean {
  return typeof window !== 'undefined'
    && typeof window.PublicKeyCredential === 'function'
    && typeof navigator !== 'undefined'
    && !!navigator.credentials;
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return list.filter(isRecord).map(d => ({
    ...(d as object),
    type: 'public-key',
    id: fromBase64Url(String(d['id'])),
  }) as PublicKeyCredentialDescriptor);
}

/** The server's creation options as `navigator.credentials.create` takes them. */
export function creationOptions(json: unknown): PublicKeyCredentialCreationOptions {
  if (!isRecord(json) || !isRecord(json['user'])) throw new Error('passkey options are malformed');
  const user = json['user'];
  return {
    ...(json as object),
    challenge: fromBase64Url(String(json['challenge'])),
    user: { ...(user as object), id: fromBase64Url(String(user['id'])) },
    excludeCredentials: descriptors(json['excludeCredentials']),
  } as PublicKeyCredentialCreationOptions;
}

/** The server's request options as `navigator.credentials.get` takes them. */
export function requestOptions(json: unknown): PublicKeyCredentialRequestOptions {
  if (!isRecord(json)) throw new Error('passkey options are malformed');
  return {
    ...(json as object),
    challenge: fromBase64Url(String(json['challenge'])),
    allowCredentials: descriptors(json['allowCredentials']),
  } as PublicKeyCredentialRequestOptions;
}

/** A credential as `PublicKeyCredential.toJSON()` gives it. */
export function credentialJson(credential: PublicKeyCredential): Json {
  const toJson = (credential as { toJSON?: () => unknown }).toJSON;
  if (typeof toJson === 'function') return toJson.call(credential) as Json;
  const response = credential.response;
  const body: Json = { clientDataJSON: toBase64Url(response.clientDataJSON) };
  if ('attestationObject' in response) {
    const attestation = response as AuthenticatorAttestationResponse;
    body['attestationObject'] = toBase64Url(attestation.attestationObject);
    body['transports'] = typeof attestation.getTransports === 'function' ? attestation.getTransports() : [];
  } else {
    const assertion = response as AuthenticatorAssertionResponse;
    body['authenticatorData'] = toBase64Url(assertion.authenticatorData);
    body['signature'] = toBase64Url(assertion.signature);
    body['userHandle'] = assertion.userHandle ? toBase64Url(assertion.userHandle) : null;
  }
  return {
    id: credential.id,
    rawId: toBase64Url(credential.rawId),
    type: credential.type,
    response: body,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

/**
 * Creates a passkey for the server's creation `options`; resolves the JSON
 * the finish route takes. Rejects when the person cancels (a
 * `NotAllowedError` from the browser).
 */
export async function createPasskey(options: unknown): Promise<Json> {
  const credential = await navigator.credentials.create({ publicKey: creationOptions(options) });
  if (!(credential instanceof PublicKeyCredential)) throw new Error('no passkey was created');
  return credentialJson(credential);
}

/** Asks the browser for a passkey answering the server's request `options`. */
export async function getPasskey(options: unknown): Promise<Json> {
  const credential = await navigator.credentials.get({ publicKey: requestOptions(options) });
  if (!(credential instanceof PublicKeyCredential)) throw new Error('no passkey was chosen');
  return credentialJson(credential);
}

/** The browser's passkey calls, as one injectable so tests can stand in. */
export interface PasskeyBrowser {
  supported(): boolean;
  create(options: unknown): Promise<Json>;
  get(options: unknown): Promise<Json>;
}

/** Q6-T2: the real browser by default. */
export const PASSKEY_BROWSER = new InjectionToken<PasskeyBrowser>('PASSKEY_BROWSER', {
  providedIn: 'root',
  factory: () => ({ supported: passkeysSupported, create: createPasskey, get: getPasskey }),
});

/** Whether `error` is the browser's answer to a cancelled passkey prompt. */
export function isPasskeyCancelled(error: unknown): boolean {
  return typeof error === 'object' && error !== null
    && (error as { name?: unknown }).name === 'NotAllowedError';
}
