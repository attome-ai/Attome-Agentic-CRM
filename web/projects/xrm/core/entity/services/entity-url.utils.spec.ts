import { describe, expect, it } from 'vitest';
import { EntityRouteRegistry } from '../entity-route-registry.service';
import {
  entityFormRoute, entityListRoute, logicalToUrlPath, resolveEntityUrlPath,
  urlPathCandidates, urlPathToLogical,
} from './entity-url.utils';

// A registry declaring loaders for a slice of what
// src/app/attome-metadata-form-loaders.ts registers, including the one real
// collision: platform `activity` and the CRM vertical's `activity`.
function registry(): EntityRouteRegistry {
  const r = new EntityRouteRegistry();
  const noop = async () => undefined;
  for (const name of [
    'user_account', 'user_account_mm_team', 'activity',
    'trd_symbol', 'trd_account', 'account', 'activity', 'cost_center', 'clause',
    'game_ban', 'bmd_work_package',
  ]) {
    r.registerLoader(name, noop);
  }
  return r;
}

function resolve(urlPath: string): string {
  const r = registry();
  return resolveEntityUrlPath(urlPath, n => r.isRegistered(n)).logicalname;
}

describe('logicalToUrlPath / urlPathToLogical', () => {
  it('keeps the xrm_ slash shape unchanged', () => {
    expect(logicalToUrlPath('user_account')).toBe('xrm/core/systemuser');
    expect(logicalToUrlPath('user_account_mm_team')).toBe('xrm/core/systemuser/mm/team');
    expect(entityListRoute('role')).toEqual(['/xrm', 'core', 'role', 'list']);
  });

  it('puts every other prefix under xrm/entity/ verbatim', () => {
    expect(logicalToUrlPath('trd_symbol')).toBe('xrm/entity/trd_symbol');
    expect(logicalToUrlPath('account')).toBe('xrm/entity/account');
    expect(logicalToUrlPath('bmd_work_package')).toBe('xrm/entity/bmd_work_package');
    expect(entityFormRoute('trd_symbol')).toEqual(['/xrm', 'entity', 'trd_symbol', 'form']);
    // An entity_* name would collide with the xrm/entity/ shape.
    expect(logicalToUrlPath('entity_x')).toBe('xrm/entity/entity_x');
  });

  it('round-trips every shape losslessly', () => {
    for (const name of [
      'entity_info', 'contact', 'user_account_mm_team', 'trd_symbol',
      'trd_backtest_run', 'account', 'cost_center', 'bmd_work_package', 'game_ban', 'entity_x',
    ]) {
      expect(urlPathToLogical(logicalToUrlPath(name))).toBe(name);
      expect(urlPathToLogical('/' + logicalToUrlPath(name))).toBe(name);
    }
  });

  it('lists the prefix-less reading as a second candidate', () => {
    expect(urlPathCandidates('xrm/trd/symbol')).toEqual(['trd_symbol', 'trd_symbol']);
    expect(urlPathCandidates('xrm/entity/account')).toEqual(['account']);
  });
});

describe('resolveEntityUrlPath', () => {
  it('resolves an xrm_ entity', () => {
    expect(resolve('xrm/core/systemuser')).toBe('user_account');
  });

  it('resolves the existing junction route /xrm/core/systemuser/mm/team/list', () => {
    expect(resolve('xrm/core/systemuser/mm/team')).toBe('user_account_mm_team');
  });

  it('resolves a trd_ entity through both its canonical and its prefix path', () => {
    expect(resolve('xrm/entity/trd_symbol')).toBe('trd_symbol');
    expect(resolve('xrm/trd/symbol')).toBe('trd_symbol');
    expect(resolve('xrm/trd/account')).toBe('trd_account');
  });

  it('resolves an unprefixed vertical entity', () => {
    expect(resolve('xrm/entity/account')).toBe('account');
    expect(resolve('xrm/entity/cost_center')).toBe('cost_center');
    // The vertical sidebar route shape used for game-ops.
    expect(resolve('xrm/entity/game_ban')).toBe('game_ban');
    // The contract-management bundle's prefix-less sidebar route.
    expect(resolve('xrm/clause')).toBe('clause');
  });

  it('resolves a three-letter project prefix', () => {
    expect(resolve('xrm/entity/bmd_work_package')).toBe('bmd_work_package');
    expect(resolve('xrm/bmd/work/package')).toBe('bmd_work_package');
  });

  it('prefers the canonical xrm_ entity when both readings are registered, and reports it', () => {
    const r = registry();
    const res = resolveEntityUrlPath('xrm/activity', n => r.isRegistered(n));
    expect(res.logicalname).toBe('activity');
    expect(res.ambiguous).toEqual(['activity', 'activity']);
    // The vertical's own entity stays reachable through its canonical URL.
    expect(resolve('xrm/entity/activity')).toBe('activity');
  });

  it('falls back to the xrm_ reading for an unregistered (list-only) entity', () => {
    const res = resolveEntityUrlPath('xrm/core/entity/info', () => false);
    expect(res).toEqual({ logicalname: 'entity_info', ambiguous: [] });
  });

  it('sees an override registered without a loader', () => {
    const r = new EntityRouteRegistry();
    r.register('trd_bar', {});
    expect(resolveEntityUrlPath('xrm/trd/bar', n => r.isRegistered(n)).logicalname).toBe('trd_bar');
  });
});
