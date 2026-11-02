import { Observable, of } from 'rxjs';

/** The parts of an `ApiService` stand-in a spec may give. */
interface ApiStandIn {
  get?: (...args: unknown[]) => Observable<unknown>;
  getBackground?: (...args: unknown[]) => Observable<unknown>;
  post?: (...args: unknown[]) => Observable<unknown>;
  put?: (...args: unknown[]) => Observable<unknown>;
  patch?: (...args: unknown[]) => Observable<unknown>;
  delete?: (...args: unknown[]) => Observable<unknown>;
  getAllPages?: (...args: unknown[]) => Observable<unknown>;
}

interface SdkOptions {
  query?: Record<string, unknown>;
  body?: unknown;
  ifMatch?: number | string;
}

/**
 * Y9-T3: an `SdkService` stand-in for a spec written against an `ApiService`
 * stand-in. Each SDK call becomes the `ApiService` call it replaced, on the
 * same stand-in, so the spec's spies and answers keep working:
 * `get(path, {query})` -> `get(path, query)`, `post(path, {body}, write)` ->
 * `post(path, body, write)`, `patch(path, {body, ifMatch}, write)` ->
 * `patch(path, body, ifMatch, write)`. Each call keeps the stand-in as
 * `this`, so a class-based stand-in's methods work.
 */
export function sdkFromApi(api: ApiStandIn): unknown {
  const missing = (..._args: unknown[]): Observable<never> => of() as Observable<never>;
  const drop = <T>(args: T[]): T[] => {
    while (args.length > 0 && args[args.length - 1] === undefined) args.pop();
    return args;
  };
  return {
    get: (path: string, opts?: SdkOptions) =>
      (api.get ?? missing).apply(api, drop([path, opts?.query])),
    getBackground: (path: string, query?: Record<string, string>) =>
      (api.getBackground ?? missing).apply(api, drop([path, query])),
    delete: (path: string, opts?: SdkOptions) =>
      (api.delete ?? missing).apply(api, drop([path, opts?.query])),
    post: (path: string, opts?: SdkOptions, write?: unknown) =>
      (api.post ?? missing).apply(api, drop([path, opts?.body, write])),
    put: (path: string, opts?: SdkOptions, write?: unknown) =>
      (api.put ?? missing).apply(api, drop([path, opts?.body, write])),
    patch: (path: string, opts?: SdkOptions, write?: unknown) =>
      (api.patch ?? missing).apply(api, drop([path, opts?.body, opts?.ifMatch, write])),
    getAllPages: (...args: unknown[]) => (api.getAllPages ?? missing).apply(api, args),
  };
}
