import { afterEach, describe, expect, it, vi } from 'vitest';

import { ManagedConfigService, managedAddress } from './managed-config.service';

const g = globalThis as unknown as { Capacitor?: unknown };

afterEach(() => {
  delete g.Capacitor;
  vi.restoreAllMocks();
});

describe('ManagedConfigService (B17-T9)', () => {
  it('deployment_url skips connect', async () => {
    const values: Record<string, unknown> = {
      deployment_url: 'https://crm.example.com/xrm',
      block_copy: true,
      lock_timeout_minutes: 2,
    };
    g.Capacitor = {
      isNativePlatform: () => true,
      Plugins: {
        ManagedConfigurations: {
          getString: vi.fn(async ({ key }: { key: string }) => ({ value: values[key] ?? null })),
          getBoolean: vi.fn(async ({ key }: { key: string }) => ({ value: values[key] ?? null })),
          getNumber: vi.fn(async ({ key }: { key: string }) => ({ value: values[key] ?? null })),
        },
      },
    };
    const config = await new ManagedConfigService().get();
    expect(config).toEqual({
      deployment_url: 'https://crm.example.com',
      block_copy: true,
      lock_timeout_minutes: 2,
    });
  });

  it('nothing is managed in a browser', async () => {
    expect(await new ManagedConfigService().get()).toEqual({
      deployment_url: null,
      block_copy: false,
      lock_timeout_minutes: null,
    });
    expect(managedAddress('http://crm.example.com')).toBeNull();
    expect(managedAddress('not a url')).toBeNull();
  });
});
