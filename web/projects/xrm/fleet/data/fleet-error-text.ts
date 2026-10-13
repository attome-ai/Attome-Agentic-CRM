import type { ApiError, LangService } from '@attome/base';

/**
 * The stable codes the console's own refusals start their message with
 * (`validation error: <code>: …`, `conflict: <code>: …`), from
 * `crates/engine/attome-fleet/src/{routes,store,changesets}.rs`. Each has a
 * `fleet.errors.<code>` catalog entry; anything else falls back to
 * `LangService.errorText`.
 */
export const FLEET_ERROR_CODES = [
  'credential_refused',
  'no_credential',
  'backup_ref_required',
  'changeset_checksum_invalid',
  'changeset_changed',
  'fleet_deployment_exists',
  'fleet_rollout_active',
  'fleet_rollout_not_running',
  'fleet_rollout_not_halted',
  'fleet_rollout_not_resumable',
  'fleet_rollout_finished',
  'fleet_target_not_planned',
  'fleet_target_nothing_to_apply',
  'fleet_target_not_skippable',
] as const;

/** The two codes that arrive as the body's `error` (not a message prefix). */
const REMOTE_ERROR = 'fleet_remote_error';
const LOOPBACK_ONLY = 'fleet_console_loopback_only';

/** `validation error: no_credential: store …` → `no_credential`, when it is one of ours. */
export function fleetErrorCode(message: unknown): string | null {
  if (typeof message !== 'string') return null;
  let rest = message.trim();
  for (const prefix of ['validation error: ', 'conflict: ']) {
    if (rest.startsWith(prefix)) rest = rest.slice(prefix.length);
  }
  const code = rest.split(':', 1)[0].trim();
  return (FLEET_ERROR_CODES as readonly string[]).includes(code) ? code : null;
}

/**
 * The user-facing text of a failed console call:
 * - a customer failure (`502 fleet_remote_error`) says the customer server
 *   refused or failed, followed by the server's short technical detail (it
 *   names the customer's status and code, never a record value);
 * - a non-loopback refusal says the console works only on this machine;
 * - one of the console's own stable codes gets its catalog sentence;
 * - anything else is `LangService.errorText`.
 */
export function fleetErrorText(
  lang: Pick<LangService, 'translate' | 'errorText'>,
  err: Pick<ApiError, 'kind' | 'code' | 'message'> | null | undefined,
): string {
  if (err?.code === REMOTE_ERROR) {
    const lead = lang.translate('fleet.errors.remote');
    const detail = typeof err.message === 'string' ? err.message.trim() : '';
    return detail ? `${lead} (${detail})` : lead;
  }
  if (err?.code === LOOPBACK_ONLY) return lang.translate('fleet.errors.loopbackOnly');
  // Only the console's own stable codes reach here, and the catalog parity
  // spec guarantees each has a sentence.
  const code = fleetErrorCode(err?.message);
  if (code) return lang.translate(`fleet.errors.${code}`);
  return lang.errorText(err);
}
