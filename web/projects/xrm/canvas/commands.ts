/**
 * Y14-T1: draft edit commands, as the server takes them
 * (`attome_model::commands::Command`, Y1-T8): JSON Pointer paths; `add`
 * inserts into an array (an index, or `-` for the end) or sets an object
 * member; `set` replaces a value; `remove` deletes; `move` removes then
 * adds, reading the destination after the removal (RFC 6902).
 */
export type EditCommand =
  | { op: 'add'; path: string; value: unknown }
  | { op: 'remove'; path: string }
  | { op: 'move'; from: string; to: string }
  | { op: 'set'; path: string; value: unknown };

type Json = unknown;
type Container = Record<string, Json> | Json[];

function segments(path: string): string[] {
  if (!path.startsWith('/')) throw new Error(`not a JSON Pointer: ${path}`);
  return path.slice(1).split('/').map(s => s.replace(/~1/g, '/').replace(/~0/g, '~'));
}

/** Escapes one pointer segment. Pure. */
export function escapeSegment(segment: string): string {
  return segment.replace(/~/g, '~0').replace(/\//g, '~1');
}

function parentOf(doc: Json, path: string): { parent: Container; key: string } {
  const parts = segments(path);
  const key = parts.pop() ?? '';
  let current: Json = doc;
  for (const p of parts) {
    if (Array.isArray(current)) current = current[Number(p)];
    else if (current && typeof current === 'object') current = (current as Record<string, Json>)[p];
    else throw new Error(`no such path: ${path}`);
  }
  if (!current || typeof current !== 'object') throw new Error(`no such path: ${path}`);
  return { parent: current as Container, key };
}

/** The value at `path`. Pure. */
export function valueAt(doc: Json, path: string): Json {
  const { parent, key } = parentOf(doc, path);
  return Array.isArray(parent) ? parent[Number(key)] : parent[key];
}

function addAt(doc: Json, path: string, value: Json): void {
  const { parent, key } = parentOf(doc, path);
  if (Array.isArray(parent)) {
    const i = key === '-' ? parent.length : Number(key);
    if (!Number.isInteger(i) || i < 0 || i > parent.length) throw new Error(`index out of range: ${path}`);
    parent.splice(i, 0, value);
  } else {
    parent[key] = value;
  }
}

function removeAt(doc: Json, path: string): Json {
  const { parent, key } = parentOf(doc, path);
  if (Array.isArray(parent)) {
    const i = Number(key);
    if (!Number.isInteger(i) || i < 0 || i >= parent.length) throw new Error(`index out of range: ${path}`);
    return parent.splice(i, 1)[0];
  }
  if (!(key in parent)) throw new Error(`no such path: ${path}`);
  const old = parent[key];
  delete parent[key];
  return old;
}

/** `doc` after `command`, leaving `doc` as it was. Throws on a path that does not apply. Pure. */
export function applyCommand<T>(doc: T, command: EditCommand): T {
  const next = structuredClone(doc) as Json;
  switch (command.op) {
    case 'add': addAt(next, command.path, structuredClone(command.value)); break;
    case 'set': {
      const { parent, key } = parentOf(next, command.path);
      if (Array.isArray(parent)) parent[Number(key)] = structuredClone(command.value);
      else parent[key] = structuredClone(command.value);
      break;
    }
    case 'remove': removeAt(next, command.path); break;
    case 'move': addAt(next, command.to, removeAt(next, command.from)); break;
  }
  return next as T;
}

/** The pointer `to` names once the value is in place (an `-` end index made concrete). Pure. */
function placed(doc: Json, to: string): string {
  if (!to.endsWith('/-')) return to;
  const parentPath = to.slice(0, -2);
  const list = parentPath === '' ? doc : valueAt(doc, parentPath);
  const length = Array.isArray(list) ? list.length : 0;
  return `${parentPath}/${length - 1}`;
}

/** The command that undoes `command` applied to `before`. Pure. */
export function inverseOf(before: Json, command: EditCommand): EditCommand {
  switch (command.op) {
    case 'add': {
      const after = applyCommand(before, command);
      return { op: 'remove', path: placed(after, command.path) };
    }
    case 'remove':
      return { op: 'add', path: command.path, value: structuredClone(valueAt(before, command.path)) };
    case 'set': {
      const { parent, key } = parentOf(before, command.path);
      const existed = Array.isArray(parent) ? Number(key) < parent.length : key in parent;
      return existed
        ? { op: 'set', path: command.path, value: structuredClone(valueAt(before, command.path)) }
        : { op: 'remove', path: command.path };
    }
    case 'move': {
      const after = applyCommand(before, command);
      return { op: 'move', from: placed(after, command.to), to: command.from };
    }
  }
}
