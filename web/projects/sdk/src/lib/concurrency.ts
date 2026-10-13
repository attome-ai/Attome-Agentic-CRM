// `If-Match`/`row_version` optimistic-concurrency helper matching the
// server's existing contract exactly
// (crates/engine/attome-api/src/entity_crud/row_version.rs, D-079/DATA-7/CONC-1,
// coding-guidelines.md §2).

/** Required on every entity `PATCH` (D-079); optional on delete/restore
 * (DATA-7/CONC-1). A missing value on `PATCH` is a 422, a mismatched one is
 * a 409 `version_conflict`. */
export const IF_MATCH_HEADER = 'If-Match';

/** Optional conditional-read short-circuit on a single-record `GET`. */
export const IF_NONE_MATCH_HEADER = 'If-None-Match';

/** Formats a `row_version` for `If-Match`/`If-None-Match`. The server
 * accepts a quoted (`"3"`) or bare (`3`) integer
 * (`row_version.rs::expected_row_version`'s doc comment) — quoted matches
 * what `@attome/base`'s `ApiService` already sends, so this SDK does the
 * same for consistency. */
export function ifMatchValue(rowVersion: number | string): string {
  return `"${rowVersion}"`;
}

/** Parses the `row_version` out of an `ETag` response header. The server
 * always emits a weak tag (`W/"3"`, `row_version_etag`) since the JSON
 * body's exact bytes aren't guaranteed stable even when `row_version` is
 * unchanged — this accepts that form and a bare/strong quoted one for
 * robustness. Returns `undefined` for a missing or unparseable header,
 * never throws. */
export function rowVersionFromETag(etag: string | null | undefined): number | undefined {
  if (!etag) return undefined;
  const stripped = etag.trim().replace(/^W\//, '').replace(/^"|"$/g, '');
  const n = Number(stripped);
  return Number.isFinite(n) ? n : undefined;
}
