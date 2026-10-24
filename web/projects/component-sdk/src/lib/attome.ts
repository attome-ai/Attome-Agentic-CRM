// T3-T1: the one object a custom component is given, `attome`. It reads and
// writes records through the platform's API as the person viewing the page,
// so their permissions apply exactly as they do anywhere else; it tells the
// page about things through events; and it reads the theme. It holds no
// credential: the host passes a transport bound to the viewer's session, and
// the component only ever sees the frozen facade, never the transport, the
// app's services or a token.

/** The part of `@attome/sdk`'s `AttomeClient` the facade needs. The host
 * passes its own client (or anything shaped like it); typed structurally so
 * this package depends on nothing. */
export interface HostTransport {
  get<T>(path: string, opts?: HostRequestOptions): Promise<{ data: T }>;
  patch<T>(path: string, opts?: HostRequestOptions): Promise<{ data: T }>;
}

export interface HostRequestOptions {
  query?: Record<string, string | number | boolean | undefined | null>;
  body?: unknown;
  ifMatch?: number | string;
}

/** What the host gives one component instance. */
export interface ComponentContext {
  transport: HostTransport;
  /** The component's host element: events are dispatched on it. */
  element: EventTarget;
  /** The design tokens in force (`--color-primary` and the like). */
  theme: () => Readonly<Record<string, string>>;
  /** The page's writing direction. */
  dir: () => 'ltr' | 'rtl';
  /** The entities the component's manifest declares (T3-T3); others are
   * refused before any request. Absent: any entity the viewer may read. */
  entities?: readonly string[];
}

/** A record as the API returns it: its fields, with `id` and `row_version`. */
export type ComponentRecord = Readonly<Record<string, unknown>> & {
  readonly id: string;
  readonly row_version?: number;
};

export interface RecordPage {
  readonly items: readonly ComponentRecord[];
  readonly total: number;
  readonly page: number;
  readonly page_size: number;
}

export interface ListOptions {
  page?: number;
  pageSize?: number;
  /** Free-text search over the entity's searchable fields. */
  search?: string;
}

export interface Attome {
  readonly records: {
    get(entity: string, id: string): Promise<ComponentRecord>;
    list(entity: string, options?: ListOptions): Promise<RecordPage>;
    /** `rowVersion` is the record's `row_version` as read; a stale one is
     * refused by the server (409) rather than overwriting someone's edit. */
    update(
      entity: string,
      id: string,
      rowVersion: number,
      values: Readonly<Record<string, unknown>>,
    ): Promise<ComponentRecord>;
  };
  readonly events: {
    /** Dispatches `attome:<name>` on the component, bubbling out of its
     * shadow root, with a copy of `detail`. */
    emit(name: string, detail?: unknown): void;
  };
  readonly theme: {
    tokens(): Readonly<Record<string, string>>;
    dir(): 'ltr' | 'rtl';
  };
}

/** A refusal the facade or the server made, without request internals. */
export class ComponentSdkError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ComponentSdkError';
  }
}

const ENTITY = /^[a-z][a-z0-9_]{0,127}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EVENT = /^[a-z][a-z0-9_.-]{0,63}$/;
/** The API's own page cap. */
export const MAX_PAGE_SIZE = 200;

function entityPath(ctx: ComponentContext, entity: string): string {
  if (!ENTITY.test(entity)) {
    throw new ComponentSdkError('invalid_entity', `not an entity name: ${entity}`);
  }
  if (ctx.entities && !ctx.entities.includes(entity)) {
    throw new ComponentSdkError('entity_not_declared', `the component does not declare ${entity}`);
  }
  return `/api/v1/${entity}`;
}

function recordPath(ctx: ComponentContext, entity: string, id: string): string {
  if (!UUID.test(id)) {
    throw new ComponentSdkError('invalid_id', 'a record id is a UUID');
  }
  return `${entityPath(ctx, entity)}/${id.toLowerCase()}`;
}

/** A plain-data copy: a component hands nothing live to the page, and the
 * page hands nothing live back. */
function copy<T>(value: T): T {
  return value === undefined ? value : (JSON.parse(JSON.stringify(value)) as T);
}

/** Server refusals keep their status and `error` code, nothing else. */
async function call<T>(request: () => Promise<{ data: T }>): Promise<T> {
  try {
    return copy((await request()).data);
  } catch (error) {
    if (error instanceof ComponentSdkError) throw error;
    const e = error as { status?: number; body?: { error?: string; message?: string }; kind?: string };
    const code = e?.body?.error ?? e?.kind ?? 'request_failed';
    const status = typeof e?.status === 'number' ? ` (${e.status})` : '';
    throw new ComponentSdkError(code, `${e?.body?.message ?? 'the request was refused'}${status}`);
  }
}

/** The `attome` object for one component instance. Frozen, all the way. */
export function createAttome(ctx: ComponentContext): Attome {
  const records = Object.freeze({
    get: async (entity: string, id: string) => {
      const path = recordPath(ctx, entity, id);
      return call<ComponentRecord>(() => ctx.transport.get(path));
    },
    list: async (entity: string, options: ListOptions = {}) => {
      const path = entityPath(ctx, entity);
      const pageSize = Math.min(Math.max(Math.trunc(options.pageSize ?? 50), 1), MAX_PAGE_SIZE);
      const page = Math.max(Math.trunc(options.page ?? 1), 1);
      return call<RecordPage>(() =>
        ctx.transport.get(path, {
          query: { page, page_size: pageSize, search: options.search || undefined },
        }),
      );
    },
    update: async (
      entity: string,
      id: string,
      rowVersion: number,
      values: Readonly<Record<string, unknown>>,
    ) => {
      const path = recordPath(ctx, entity, id);
      if (!Number.isInteger(rowVersion) || rowVersion < 0) {
        throw new ComponentSdkError('invalid_row_version', "rowVersion is the record's row_version");
      }
      return call<ComponentRecord>(() =>
        ctx.transport.patch(path, { body: copy(values), ifMatch: rowVersion }),
      );
    },
  });
  const events = Object.freeze({
    emit: (name: string, detail?: unknown) => {
      if (!EVENT.test(name)) {
        throw new ComponentSdkError('invalid_event', `not an event name: ${name}`);
      }
      ctx.element.dispatchEvent(
        new CustomEvent(`attome:${name}`, { detail: copy(detail), bubbles: true, composed: true }),
      );
    },
  });
  const theme = Object.freeze({
    tokens: () => Object.freeze({ ...ctx.theme() }),
    dir: () => ctx.dir(),
  });
  return Object.freeze({ records, events, theme });
}
