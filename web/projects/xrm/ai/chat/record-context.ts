import type { RecordContext } from './services/chat.service';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** The same shape the server checks (`chat_view::is_logical_name`). */
const LOGICAL_NAME = /^[a-z][a-z0-9_]{0,62}$/;

/**
 * The record the user is looking at, read from the router URL of an entity
 * form — `/xrm/<entity path>/form?id=<uuid>` (`entityFormRoute`'s shape, whose
 * path maps 1:1 onto the logical name). `null` anywhere else, including a form
 * with no record yet.
 *
 * **Navigation state, never authorization (I-19, row A-66).** This is only
 * what the address bar says. The server stores it as part of the user's
 * message and never looks the record up for it; whether the user may read the
 * record is decided by the ordinary action path when, and only if, the
 * assistant tries to.
 */
export function recordContextFromUrl(url: string): RecordContext | null {
  const [path, query = ''] = url.split('#')[0].split('?');
  const segments = path.split('/').filter(Boolean);
  if (segments.length < 3 || segments[0] !== 'xrm' || segments[segments.length - 1] !== 'form') {
    return null;
  }
  const entity = segments.slice(0, -1).join('_');
  const id = new URLSearchParams(query).get('id');
  if (!id || !UUID.test(id) || !LOGICAL_NAME.test(entity)) return null;
  return { entity, record_id: id.toLowerCase() };
}
