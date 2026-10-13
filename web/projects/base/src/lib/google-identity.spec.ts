import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * NGB-6.1c — GSI's `initialize()` may only run once per page (the library
 * warns and drops the origin check intermittently when re-invoked), while
 * several components each want their own callback. So: one real initialize,
 * one stable indirection, last registrant wins.
 *
 * `vi.resetModules()` + a dynamic import gives each case a fresh module, since
 * the "already initialized" flag is module state by design.
 */
describe('initGoogleIdentityOnce', () => {
  let initialize: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.resetModules();
    initialize = vi.fn();
    (globalThis as unknown as { google: unknown }).google = {
      accounts: { id: { initialize, renderButton: vi.fn() } },
    };
  });

  afterEach(() => {
    delete (globalThis as unknown as { google?: unknown }).google;
  });

  it('initializes the library once and routes its callback to the last registrant', async () => {
    const { initGoogleIdentityOnce } = await import('./google-identity');
    const first = vi.fn();
    const second = vi.fn();

    initGoogleIdentityOnce({ client_id: 'client-a', callback: first });
    initGoogleIdentityOnce({ client_id: 'client-b', callback: second });

    expect(initialize).toHaveBeenCalledTimes(1);
    const config = initialize.mock.calls[0][0] as { client_id: string; callback: (r: { credential: string }) => void };
    expect(config.client_id).toBe('client-a');

    config.callback({ credential: 'a-credential' });

    expect(second).toHaveBeenCalledWith({ credential: 'a-credential' });
    expect(first).not.toHaveBeenCalled();
  });

  it('forwards the extra options only on the one real initialize call', async () => {
    const { initGoogleIdentityOnce } = await import('./google-identity');
    const callback = vi.fn();

    initGoogleIdentityOnce({ client_id: 'client-a', callback, auto_select: true, cancel_on_tap_outside: false });

    const config = initialize.mock.calls[0][0] as Record<string, unknown>;
    expect(config['auto_select']).toBe(true);
    expect(config['cancel_on_tap_outside']).toBe(false);
    expect(config['client_id']).toBe('client-a');
    expect(config['callback']).toBeTypeOf('function');
  });
});
