import { describe, expect, it } from 'vitest';
import { ComponentSdkError, createAttome, type ComponentContext, type HostRequestOptions } from './attome';

const ID = '0192f0c4-7d1e-7c3a-9b1e-5d6f8a9b0c1d';

interface Call {
  method: 'GET' | 'PATCH';
  path: string;
  opts?: HostRequestOptions;
}

function host(answer: unknown = { id: ID, row_version: 3, name: 'Acme' }, entities?: readonly string[]) {
  const calls: Call[] = [];
  const element = new EventTarget();
  const ctx: ComponentContext = {
    transport: {
      get: async <T>(path: string, opts?: HostRequestOptions) => {
        calls.push({ method: 'GET', path, opts });
        return { data: answer as T };
      },
      patch: async <T>(path: string, opts?: HostRequestOptions) => {
        calls.push({ method: 'PATCH', path, opts });
        return { data: answer as T };
      },
    },
    element,
    theme: () => ({ '--color-primary': '#0a6' }),
    dir: () => 'rtl',
    entities,
  };
  return { attome: createAttome(ctx), calls, element };
}

describe('createAttome (T3-T1)', () => {
  it('reads, lists and updates records through the host transport', async () => {
    const { attome, calls } = host();
    const record = await attome.records.get('account', ID.toUpperCase());
    expect(record.name).toBe('Acme');
    await attome.records.list('account', { page: 2, pageSize: 500, search: 'ac' });
    await attome.records.update('account', ID, 3, { name: 'Acme Ltd' });
    expect(calls).toEqual([
      { method: 'GET', path: `/api/v1/account/${ID}`, opts: undefined },
      { method: 'GET', path: '/api/v1/account', opts: { query: { page: 2, page_size: 200, search: 'ac' } } },
      { method: 'PATCH', path: `/api/v1/account/${ID}`, opts: { body: { name: 'Acme Ltd' }, ifMatch: 3 } },
    ]);
  });

  it('refuses a bad name, id or version, and an entity the manifest does not declare', async () => {
    const { attome, calls } = host(undefined, ['account']);
    await expect(attome.records.get('../admin', ID)).rejects.toMatchObject({ code: 'invalid_entity' });
    await expect(attome.records.get('account', 'not-an-id')).rejects.toMatchObject({ code: 'invalid_id' });
    await expect(attome.records.list('contact')).rejects.toMatchObject({ code: 'entity_not_declared' });
    await expect(attome.records.update('account', ID, -1, {})).rejects.toBeInstanceOf(ComponentSdkError);
    expect(calls).toEqual([]);
  });

  it('keeps only the status and code of a server refusal', async () => {
    const { attome } = host();
    const failing = createAttome({
      transport: {
        get: async () => {
          throw { status: 409, body: { error: 'version_conflict', message: 'version conflict' }, secret: 'x' };
        },
        patch: async <T>() => ({ data: {} as T }),
      },
      element: new EventTarget(),
      theme: () => ({}),
      dir: () => 'ltr',
    });
    const error = await failing.records.get('account', ID).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ComponentSdkError);
    expect((error as ComponentSdkError).code).toBe('version_conflict');
    expect(String((error as Error).message)).not.toContain('secret');
    expect(attome).toBeDefined();
  });

  it('emits copies of its events on the component and reads the theme', () => {
    const { attome, element } = host();
    const seen: CustomEvent[] = [];
    element.addEventListener('attome:selected', (e) => seen.push(e as CustomEvent));
    const detail = { id: ID };
    attome.events.emit('selected', detail);
    expect(seen).toHaveLength(1);
    expect(seen[0].detail).toEqual(detail);
    expect(seen[0].detail).not.toBe(detail);
    expect(seen[0].bubbles && seen[0].composed).toBe(true);
    expect(() => attome.events.emit('Bad Name')).toThrow(ComponentSdkError);
    expect(attome.theme.tokens()['--color-primary']).toBe('#0a6');
    expect(attome.theme.dir()).toBe('rtl');
  });

  it('cannot be changed by the component', () => {
    const { attome } = host();
    expect(Object.isFrozen(attome)).toBe(true);
    expect(Object.isFrozen(attome.records)).toBe(true);
    expect(() => {
      (attome.records as { get: unknown }).get = () => null;
    }).toThrow();
    expect(Object.keys(attome)).toEqual(['records', 'events', 'theme']);
  });
});
