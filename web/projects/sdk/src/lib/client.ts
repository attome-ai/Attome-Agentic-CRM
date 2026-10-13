import { AttomeTransport } from './transport';
import type { AttomeClientOptions, ApiResponse, RequestOptions } from './transport';
import { paginate, type PaginatedResponse } from './pagination';

/** High-level convenience wrapper over `AttomeTransport`. Construct one per
 * (deployment, auth) pair — it is stateless beyond that, so it is safe to
 * share across concurrent requests. */
export class AttomeClient {
  private readonly transport: AttomeTransport;

  constructor(options: AttomeClientOptions) {
    this.transport = new AttomeTransport(options);
  }

  get<T>(path: string, opts?: RequestOptions): Promise<ApiResponse<T>> {
    return this.transport.request<T>('GET', path, opts);
  }

  post<T>(path: string, opts?: RequestOptions): Promise<ApiResponse<T>> {
    return this.transport.request<T>('POST', path, opts);
  }

  /** Entity updates require `opts.ifMatch` (the record's current
   * `row_version`) — the server rejects a versionless `PATCH` with a 422
   * (D-079). Read it off a prior `get`'s `ETag` response header via
   * `rowVersionFromETag`, or off the record body's own `row_version` field. */
  patch<T>(path: string, opts?: RequestOptions): Promise<ApiResponse<T>> {
    return this.transport.request<T>('PATCH', path, opts);
  }

  put<T>(path: string, opts?: RequestOptions): Promise<ApiResponse<T>> {
    return this.transport.request<T>('PUT', path, opts);
  }

  delete<T>(path: string, opts?: RequestOptions): Promise<ApiResponse<T>> {
    return this.transport.request<T>('DELETE', path, opts);
  }

  /** Iterates every item across every page of a `PaginatedResponse<T>` list
   * endpoint (coding-guidelines.md §12), fetching one page at a time.
   *
   * ```ts
   * for await (const contact of client.paginate<Contact>('/api/v1/contact')) { ... }
   * ```
   */
  paginate<T>(path: string, opts: RequestOptions = {}, startPage = 1): AsyncGenerator<T, void, unknown> {
    return paginate<T>(
      (page) => this.get<PaginatedResponse<T>>(path, { ...opts, query: { ...opts.query, page } }).then((r) => r.data),
      startPage,
    );
  }
}
