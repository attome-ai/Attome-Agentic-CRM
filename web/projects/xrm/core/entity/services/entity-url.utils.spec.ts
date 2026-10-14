import { describe, expect, it } from 'vitest';
import { EntityRouteRegistry } from '../entity-route-registry.service';
import {
  entityFormRoute, entityListRoute, logicalToUrlPath, resolveEntityUrlPath,
  urlPathCandidates, urlPathToLogical,
} from './entity-url.utils';

// A registry declaring loaders for a slice of what
// src/app/attome-metadata-form-loaders.ts registers.
function registry(): EntityRouteRegistry {
  const r = new EntityRouteRegistry();
  const noop = async () => undefined;
  for (const name of [
    'user_account', 'user_account_mm_team', 'activity', 'account', 'cost_center', 'clause',
    'bmd_work_package',
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
  it('puts every logical name under xrm/entity/ verbatim', () => {
    expect(logicalToUrlPath('user_account')).toBe('xrm/entity/user_account');
    expect(logicalToUrlPath('user_account_mm_team')).toBe('xrm/entity/user_account_mm_team');
    expect(logicalToUrlPath('bmd_work_package')).toBe('xrm/entity/bmd_work_package');
    expect(entityListRoute('role')).toEqual(['/xrm', 'entity', 'role', 'list']);
    expect(entityFormRoute('account')).toEqual(['/xrm', 'entity', 'account', 'form']);
  });

  it('round-trips every name losslessly', () => {
    for (const name of [
      'entity_info', 'contact', 'user_account_mm_team', 'account', 'cost_center',
      'bmd_work_package', 'entity_x',
    ]) {
      expect(urlPathToLogical(logicalToUrlPath(name))).toBe(name);
      expect(urlPathToLogical('/' + logicalToUrlPath(name))).toBe(name);
    }
  });

  it('lists the short reading as a second candidate', () => {
    expect(urlPathCandidates('xrm/clause')).toEqual(['xrm_clause', 'clause']);
    expect(urlPathCandidates('xrm/bmd/work/package')).toEqual([
      'xrm_bmd_work_package', 'bmd_work_package',
    ]);
    expect(urlPathCandidates('xrm/entity/account')).toEqual(['account']);
  });
});

describe('resolveEntityUrlPath', () => {
  it('resolves the canonical path', () => {
    expect(resolve('xrm/entity/user_account')).toBe('user_account');
    expect(resolve('xrm/entity/user_account_mm_team')).toBe('user_account_mm_team');
    expect(resolve('xrm/entity/cost_center')).toBe('cost_center');
  });

  it('resolves a short pack sidebar route', () => {
    expect(resolve('xrm/clause')).toBe('clause');
    expect(resolve('xrm/activity')).toBe('activity');
  });

  it('resolves a three-letter project prefix', () => {
    expect(resolve('xrm/entity/bmd_work_package')).toBe('bmd_work_package');
    expect(resolve('xrm/bmd/work/package')).toBe('bmd_work_package');
  });

  it('falls back to the canonical reading for an unregistered (list-only) entity', () => {
    const res = resolveEntityUrlPath('xrm/entity/entity_info', () => false);
    expect(res).toEqual({ logicalname: 'entity_info', ambiguous: [] });
  });

  it('sees an override registered without a loader', () => {
    const r = new EntityRouteRegistry();
    r.register('bmd_bar', {});
    expect(resolveEntityUrlPath('xrm/bmd/bar', n => r.isRegistered(n)).logicalname).toBe('bmd_bar');
  });
});
