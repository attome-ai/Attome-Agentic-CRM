import { describe, expect, it } from 'vitest';
import { fleetErrorCode, fleetErrorText } from './fleet-error-text';

const lang = {
  translate: (key: string) => (key.startsWith('fleet.errors.') ? `T:${key}` : key),
  errorText: () => 'GENERIC',
};

describe('fleetErrorText', () => {
  it('names a customer failure and keeps the server\'s short detail', () => {
    const text = fleetErrorText(lang, {
      kind: 'unknown', code: 'fleet_remote_error',
      message: 'the customer server refused or failed: timeout',
    });
    expect(text).toBe('T:fleet.errors.remote (the customer server refused or failed: timeout)');
  });

  it('names a non-loopback refusal', () => {
    expect(fleetErrorText(lang, { kind: 'forbidden', code: 'fleet_console_loopback_only', message: '' }))
      .toBe('T:fleet.errors.loopbackOnly');
  });

  it('turns the console\'s own stable codes into catalog text', () => {
    expect(fleetErrorText(lang, {
      kind: 'validation', code: 'validation_error',
      message: 'validation error: backup_ref_required: a prod deployment needs …',
    })).toBe('T:fleet.errors.backup_ref_required');
    expect(fleetErrorText(lang, {
      kind: 'conflict', code: 'conflict', message: 'conflict: fleet_rollout_active: another rollout …',
    })).toBe('T:fleet.errors.fleet_rollout_active');
  });

  it('falls back to the generic text for anything else', () => {
    expect(fleetErrorText(lang, { kind: 'version_conflict', code: 'version_conflict', message: 'version conflict' }))
      .toBe('GENERIC');
    expect(fleetErrorText(lang, null)).toBe('GENERIC');
  });

  it('reads only known codes', () => {
    expect(fleetErrorCode('validation error: no_credential: store it first')).toBe('no_credential');
    expect(fleetErrorCode('validation error: label: required')).toBeNull();
    expect(fleetErrorCode(undefined)).toBeNull();
  });
});
