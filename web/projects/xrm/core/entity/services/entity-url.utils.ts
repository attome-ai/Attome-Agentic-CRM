/**
 * Entity logical name <-> URL path, relative to the site root, without the
 * trailing 'list'/'form' action.
 *
 * Logical names do not share one prefix: platform entities are
 * `xrm_{module}_{entity}`, the code-created trading entities are `trd_*`,
 * vertical bundle entities have none (`account`, `cost_center`), and project
 * entities carry a three-letter code (`bmd_*`, SYSTEM-CHANGES Topic 15 #10).
 * A single "underscore becomes slash" rule cannot tell `/xrm/activity` (the
 * platform `activity`) from the CRM vertical's `activity`, so there are
 * two canonical shapes, and together they are a lossless bijection:
 *
 *   entity_info  ->  xrm/core/entity/info    (every `_` becomes `/`)
 *   contact           ->  xrm/contact
 *   trd_symbol            ->  xrm/entity/trd_symbol   (verbatim after `xrm/entity/`)
 *   account               ->  xrm/entity/account
 *   bmd_work_package      ->  xrm/entity/bmd_work_package
 *
 * The `xrm/entity/{logicalname}` shape is the one the vertical bundles'
 * sidebar routes already use (`verticals/*\/bundle.json`,
 * `/xrm/entity/account/list`). An `entity_*` name would collide with it,
 * so it takes the verbatim shape too (none exists today).
 */
const ENTITY_PREFIX = 'xrm/entity/';

function usesSlashShape(logicalname: string): boolean {
  return logicalname.startsWith('xrm_') && !logicalname.startsWith('entity_');
}

function trimSlashes(urlPath: string): string {
  return urlPath.replace(/^\/+/, '').replace(/\/+$/, '');
}

/** Canonical URL path for a logical name (see the file comment). */
export function logicalToUrlPath(logicalname: string): string {
  return usesSlashShape(logicalname)
    ? logicalname.replace(/_/g, '/')
    : `${ENTITY_PREFIX}${logicalname}`;
}

/**
 * Exact inverse of `logicalToUrlPath` — no lookup, so it only knows the
 * canonical shapes:
 *   urlPathToLogical('xrm/core/entity/info')  -> 'entity_info'
 *   urlPathToLogical('xrm/entity/trd_symbol') -> 'trd_symbol'
 * A non-canonical path such as `xrm/trd/symbol` comes back as
 * `trd_symbol`; `resolveEntityUrlPath` is the registry-aware resolver
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
 *   'xrm/core/role'       -> ['role', 'core_role']
 *   'xrm/trd/symbol'      -> ['trd_symbol', 'trd_symbol']
 *   'xrm/clause'          -> ['clause', 'clause']
 *   'xrm/entity/account'  -> ['account']
 * The second candidate keeps working the prefix-less paths already in
 * links and bundles (`/xrm/clause/list` in the contract-management
 * vertical) and the natural `/xrm/{prefix}/{entity}` spelling of a `trd_` or
 * project-prefixed entity.
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
 *   entityMatchesUrlPath('entity_info', 'xrm/core/entity/info') → true
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
 *   entityListRoute('entity_info') → ['/xrm','core','entity','info','list']
 *   entityListRoute('trd_symbol')           → ['/xrm','entity','trd_symbol','list']
 */
export function entityListRoute(logicalname: string): string[] {
  return entityRoute(logicalname, 'list');
}

/**
 * Angular navigate() commands for the entity form page.
 * Pass { queryParams: { id: recordId } } for edit mode.
 *   entityFormRoute('entity_info') → ['/xrm','core','entity','info','form']
 */
export function entityFormRoute(logicalname: string): string[] {
  return entityRoute(logicalname, 'form');
}
