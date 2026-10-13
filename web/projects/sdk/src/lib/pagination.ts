// Pagination helpers matching `attome_types::PaginatedResponse<T>`'s envelope
// exactly (coding-guidelines.md §12): `{ items, total, page, page_size }`.

/** Mirror of `attome_types::PaginatedResponse<T>` (crates/foundation/attome-types/src/types.rs). */
export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

/** Default cap for `collectAllPages` — a deliberate guard against an
 * unbounded fetch-all against a list the server allows to grow without
 * limit; override per call when a larger bound is genuinely needed. The same
 * value as `@attome/base`'s `MAX_ALL_PAGES_ITEMS`, for the same reason: at the
 * server's `MAX_PAGE_SIZE` of 200 it is already 50 sequential requests, so a
 * list past it has outgrown "fetch everything". Keep the two equal. */
export const MAX_ALL_PAGES_ITEMS = 10_000;

/** Lazily walks every page of a `PaginatedResponse<T>` list endpoint,
 * yielding items one at a time and requesting the next page only when the
 * caller asks for more. `fetchPage` is given a 1-based page number — pass a
 * closure that calls the paginated endpoint with `page` in its query. */
export async function* paginate<T>(
  fetchPage: (page: number) => Promise<PaginatedResponse<T>>,
  startPage = 1,
): AsyncGenerator<T, void, unknown> {
  let page = startPage;
  let seen = 0;
  for (;;) {
    const resp = await fetchPage(page);
    for (const item of resp.items) {
      yield item;
      seen++;
    }
    // Stop on an empty page (defensive against a page_size/total mismatch)
    // or once every item the server reported has been seen.
    if (resp.items.length === 0 || seen >= resp.total) return;
    page++;
  }
}

/** Eagerly collects every item across every page, up to `maxItems`
 * (default `MAX_ALL_PAGES_ITEMS`). Prefer `paginate` for a large or
 * unbounded list — this loads the whole result into memory. */
export async function collectAllPages<T>(
  fetchPage: (page: number) => Promise<PaginatedResponse<T>>,
  opts: { startPage?: number; maxItems?: number } = {},
): Promise<T[]> {
  const max = opts.maxItems ?? MAX_ALL_PAGES_ITEMS;
  const out: T[] = [];
  for await (const item of paginate(fetchPage, opts.startPage)) {
    out.push(item);
    if (out.length >= max) break;
  }
  return out;
}
