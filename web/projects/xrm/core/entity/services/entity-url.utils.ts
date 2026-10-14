/**
 * Entity logical name <-> URL path, relative to the site root, without the
 * trailing 'list'/'form' action.
 *
 * Logical names carry no module prefix (V2-D483): `user_account`, `contact`,
 * `account`, `bmd_work_package`. The one canonical shape is
 *
 *   <logicalname>  ->  xrm/entity/<logicalname>   (verbatim)
 *
 * which is a lossless bijection, since a logical name never contains a slash.
 * Shorter spellings, such as `/xrm/clause/list` in a sidebar route, still
 * resolve through `urlPathCandidates`: every `/` after `xrm/` read as `_`.
 */
const ENTITY_PREFIX = 'xrm/entity/';

function trimSlashes(urlPath: string): string {
  return urlPath.replace(/^\/+/, '').replace(/\/+$/, '');
}

/** Canonical URL path for a logical name (see the file comment). */
export function logicalToUrlPath(logicalname: string): string {
  return `${ENTITY_PREFIX}${logicalname}`;
}

/**
 * Exact inverse of `logicalToUrlPath` — no lookup, so it only knows the
 * canonical shapes:
 *   urlPathToLogical('xrm/entity/user_account') -> 'user_account'
 * A non-canonical path such as `xrm/work/package` comes back as
 * `xrm_work_package`'s bare reading `work_package` only through
 * `urlPathCandidates`; `resolveEntityUrlPath` is the registry-aware resolver
 * the entity router uses for those.
 */
export function urlPathToLogical(urlPath: string): string {
  const path = trimSlashes(urlPath);
  if (path.startsWith(ENTITY_PREFIX) && path.length > ENTITY_PREFIX.length) {
    return path.slice(ENTITY_PREFIX.length).replace(/\//g, '_');
  }
  return path.replace(/\//g, '_');
}

/**
 * Every logical name a URL path can mean, most-canonical first:
 *   'xrm/entity/account'      -> ['account']
 *   'xrm/clause'              -> ['xrm_clause', 'clause']
 *   'xrm/bmd/work/package'    -> ['xrm_bmd_work_package', 'bmd_work_package']
 * The second candidate keeps working the short paths already in links and
 * pack sidebar routes (`/xrm/clause/list`) and the `/xrm/{prefix}/{entity}`
 * spelling of a project-prefixed entity.
 */
export function urlPathCandidates(urlPath: string): string[] {
  const path = trimSlashes(urlPath);
  const candidates = [urlPathToLogical(path)];
  if (path.startsWith('xrm/') && !path.startsWith(ENTITY_PREFIX)) {
    const bare = path.slice('xrm/'.length).replace(/\//g, '_');
    if (bare && !candidates.includes(bare)) candidates.push(bare);
  }
  return candidates;
}

export interface EntityUrlResolution {
  logicalname: string;
  /** Every candidate that is registered when more than one is — the caller
   * logs it. Empty when the path is unambiguous. */
  ambiguous: string[];
}

/**
 * Resolves a URL path to a logical name for any prefix. The first candidate
 * (`urlPathCandidates`) that `isRegistered` accepts wins, so a registered
 * canonical name always beats the prefix-less reading; when none is
 * registered (a list-only entity) the canonical inverse is used, which is
 * exactly the pre-existing behaviour for every `/xrm/{module}/{entity}` URL.
 */
export function resolveEntityUrlPath(
  urlPath: string,
  isRegistered: (logicalname: string) => boolean,
): EntityUrlResolution {
  const candidates = urlPathCandidates(urlPath);
  const registered = candidates.filter(isRegistered);
  return {
    logicalname: registered[0] ?? candidates[0],
    ambiguous: registered.length > 1 ? registered : [],
  };
}

/**
 * Returns true when an entity's logical name corresponds to the given URL path.
 *   entityMatchesUrlPath('entity_info', 'xrm/entity/entity_info') → true
 */
export function entityMatchesUrlPath(logicalname: string, urlPath: string): boolean {
  return logicalname === urlPathToLogical(urlPath);
}

/** Angular navigate() commands, shared by entityListRoute/entityFormRoute. */
function entityRoute(logicalname: string, action: 'list' | 'form'): string[] {
  const [root, ...rest] = logicalToUrlPath(logicalname).split('/');
  return ['/' + root, ...rest, action];
}

/**
 * Angular navigate() commands for the entity list page.
 *   entityListRoute('user_account') → ['/xrm','entity','user_account','list']
 */
export function entityListRoute(logicalname: string): string[] {
  return entityRoute(logicalname, 'list');
}

/**
 * Angular navigate() commands for the entity form page.
 * Pass { queryParams: { id: recordId } } for edit mode.
 *   entityFormRoute('user_account') → ['/xrm','entity','user_account','form']
 */
export function entityFormRoute(logicalname: string): string[] {
  return entityRoute(logicalname, 'form');
}
