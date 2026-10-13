// Public API surface of @attome/sdk (M68 Developer Platform Phase 1).
//
// A framework-agnostic TypeScript client for the platform's HTTP API,
// generated from the committed `openapi.json` (wire types) plus a
// hand-authored runtime that matches this platform's actual conventions —
// auth (session cookie / API key / S2S HMAC), pagination
// (`attome_types::PaginatedResponse<T>`), idempotency keys, `If-Match`/
// `row_version` optimistic concurrency, and the `AppError` JSON error
// contract. See `document/decisions/runtime/D-469.md` for why this SDK (and
// webhooks/S2S) is the sanctioned way to extend the platform, never
// in-process plugins.

// Generated wire types — regenerate with `npm run generate:api` from
// angular/ (writes this package's copy too; see generate-api-types.mjs).
// CI's `openapi` job fails on drift between these and the committed
// openapi.json.
export type { paths as ApiPaths, components as ApiComponents, operations as ApiOperations } from './lib/generated/api-types';

export { AttomeClient } from './lib/client';
export { AttomeTransport, CHANGESET_HEADER } from './lib/transport';
export type { AttomeClientOptions, RequestOptions, ApiResponse } from './lib/transport';

export { ApiKeyAuth } from './lib/auth/api-key';
export { SessionAuth } from './lib/auth/session';
export { S2sAuth } from './lib/auth/s2s';
export type { S2sAuthOptions } from './lib/auth/s2s';
export type { AuthProvider, AuthRequestContext } from './lib/auth/types';

export { paginate, collectAllPages, MAX_ALL_PAGES_ITEMS } from './lib/pagination';
export type { PaginatedResponse } from './lib/pagination';

export { generateIdempotencyKey, IDEMPOTENCY_KEY_HEADER } from './lib/idempotency';
export { ifMatchValue, rowVersionFromETag, IF_MATCH_HEADER, IF_NONE_MATCH_HEADER } from './lib/concurrency';

export { ApiError, mapErrorResponse, reauthDetails } from './lib/errors';
export type { ApiErrorKind, ApiErrorBody, ReauthDetails } from './lib/errors';
