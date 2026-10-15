import { firstValueFrom, of, toArray } from 'rxjs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { IdlePreloading, preloadAllowed } from './idle-preloading';

describe('IdlePreloading (AA12-T1)', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('preloads only a route that opts in, once the browser is idle', async () => {
    vi.stubGlobal('requestIdleCallback', (cb: () => void) => {
      cb();
      return 1;
    });
    const strategy = new IdlePreloading();
    const load = vi.fn(() => of('chunk'));

    expect(await firstValueFrom(strategy.preload({ path: 'a' }, load).pipe(toArray()))).toEqual([]);
    expect(load).not.toHaveBeenCalled();

    expect(await firstValueFrom(strategy.preload({ path: 'b', data: { preload: true } }, load))).toBe('chunk');
    expect(load).toHaveBeenCalledTimes(1);
  });

  it('holds back when the person saves data or the connection is 2G', () => {
    expect(preloadAllowed({})).toBe(true);
    expect(preloadAllowed({ connection: { effectiveType: '4g' } })).toBe(true);
    expect(preloadAllowed({ connection: { saveData: true } })).toBe(false);
    expect(preloadAllowed({ connection: { effectiveType: '2g' } })).toBe(false);
    expect(preloadAllowed({ connection: { effectiveType: 'slow-2g' } })).toBe(false);
  });
});
