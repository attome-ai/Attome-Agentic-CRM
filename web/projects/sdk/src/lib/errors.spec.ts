import { describe, expect, it } from 'vitest';
import { ApiError, mapErrorResponse, reauthDetails } from './errors';

describe('mapErrorResponse', () => {
  it('maps every AppError code this SDK knows about to its typed kind', () => {
    // Mirrors attome-types/src/error.rs::IntoResponse's match arms exactly —
    // one entry per variant, same code string.
    const cases: [string, number][] = [
      ['not_found', 404],
      ['unauthorized', 401],
      ['forbidden', 403],
      ['conflict', 409],
      ['version_conflict', 409],
      ['idempotency_conflict', 409],
      ['validation_error', 422],
      ['customer_tests_failed', 422],
  // D-472 / BTY-3: the rule-violation code every contract surface must carry.
  ['rule_violation', 422],
      ['field_locked', 422],
      ['field_locked_required', 422],
      ['feature_unavailable', 503],
      ['feature_hidden', 403],
      ['rate_limit_exceeded', 429],
      ['overloaded', 503],
      ['capability_unavailable', 503],
      ['metadata_authoring_locked', 403],
      ['transition_not_allowed', 422],
      ['server_timeout', 503],
      ['payload_too_large', 413],
      ['idempotency_outcome_unknown', 409],
      ['idempotency_replay_unavailable', 409],
      ['reauth_required', 401],
      ['method_not_allowed', 405],
      ['internal_error', 500],
    ];

    for (const [code, status] of cases) {
      const err = mapErrorResponse(status, 'req-1', { error: code, message: 'x', request_id: 'req-1' });
      expect(err.kind).toBe(code);
      expect(err.code).toBe(code);
      expect(err.status).toBe(status);
      expect(err.requestId).toBe('req-1');
      expect(err).toBeInstanceOf(ApiError);
    }
  });

  it('falls back to unknown_error for a code this SDK does not recognise', () => {
    const err = mapErrorResponse(400, null, { error: 'some_future_code', message: 'new thing' });
    expect(err.kind).toBe('unknown_error');
    expect(err.code).toBe('some_future_code');
    expect(err.message).toBe('new thing');
  });

  it('never throws on a malformed or missing body, and still carries the status', () => {
    expect(mapErrorResponse(500, null, undefined).status).toBe(500);
    expect(mapErrorResponse(502, null, 'not json').kind).toBe('unknown_error');
    expect(mapErrorResponse(502, null, 'not json').code).toBe('http_502');
    expect(mapErrorResponse(503, null, { message: 42 }).message).toBe('request failed with status 503');
  });

  it('prefers the body request_id over the header, but falls back to the header', () => {
    expect(mapErrorResponse(404, 'header-id', { error: 'not_found', request_id: 'body-id' }).requestId).toBe(
      'body-id',
    );
    expect(mapErrorResponse(404, 'header-id', { error: 'not_found' }).requestId).toBe('header-id');
  });

  it('marks a 5xx and rate_limit_exceeded as retryable, and every other 4xx as not', () => {
    expect(mapErrorResponse(500, null, { error: 'internal_error' }).isRetryable).toBe(true);
    expect(mapErrorResponse(503, null, { error: 'overloaded' }).isRetryable).toBe(true);
    expect(mapErrorResponse(429, null, { error: 'rate_limit_exceeded' }).isRetryable).toBe(true);
    expect(mapErrorResponse(404, null, { error: 'not_found' }).isRetryable).toBe(false);
    expect(mapErrorResponse(422, null, { error: 'validation_error' }).isRetryable).toBe(false);
  });

  it('exposes a reauth_required body through reauthDetails, and is never retryable', () => {
    const err = mapErrorResponse(401, null, {
      error: 'reauth_required',
      message: 're-authentication is required for this operation',
      operation: 'api_key_create',
      acceptable_factors: ['password', 'federated', 42],
      request_id: 'req-9',
    });
    expect(err.kind).toBe('reauth_required');
    expect(err.isRetryable).toBe(false);
    // Non-string factor entries are dropped rather than trusted.
    expect(reauthDetails(err)).toEqual({ operation: 'api_key_create', acceptableFactors: ['password', 'federated'] });
  });

  it('returns null from reauthDetails for any other error or a malformed reauth body', () => {
    expect(reauthDetails(mapErrorResponse(401, null, { error: 'unauthorized', operation: 'x' }))).toBeNull();
    expect(reauthDetails(mapErrorResponse(401, null, { error: 'reauth_required' }))).toBeNull();
    expect(reauthDetails(mapErrorResponse(401, null, { error: 'reauth_required', operation: 'identity_link' }))).toEqual({
      operation: 'identity_link',
      acceptableFactors: [],
    });
  });

  it('is a real Error subclass usable with try/catch and instanceof', () => {
    let caught: unknown;
    try {
      throw mapErrorResponse(409, null, { error: 'version_conflict', message: 'stale row_version' });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(Error);
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).message).toBe('stale row_version');
  });
});
