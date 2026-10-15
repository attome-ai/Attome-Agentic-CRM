import { TestBed } from '@angular/core/testing';
import { afterEach, describe, expect, it } from 'vitest';

import { PaletteUses, entityMatchesPrefix, parsePaletteQuery, rankByUse } from './palette';

describe('command palette (B10-T1)', () => {
  afterEach(() => localStorage.removeItem('attome.palette.uses'));

  it('reads the > and entity prefixes', () => {
    expect(parsePaletteQuery('> save')).toEqual({ scope: 'commands', entityPrefix: null, text: 'save' });
    expect(parsePaletteQuery('acc: Acme Ltd')).toEqual({ scope: 'records', entityPrefix: 'acc', text: 'Acme Ltd' });
    expect(parsePaletteQuery('  invoices ')).toEqual({ scope: 'all', entityPrefix: null, text: 'invoices' });
    // A time or a URL is not a prefix.
    expect(parsePaletteQuery('10:30').scope).toBe('all');
  });

  it('matches an entity by its name or one of its parts', () => {
    expect(entityMatchesPrefix('account', 'acc')).toBe(true);
    expect(entityMatchesPrefix('crm_contact', 'con')).toBe(true);
    expect(entityMatchesPrefix('account', 'con')).toBe(false);
  });

  it('puts the page\'s own commands first, then the most used', () => {
    const items = [
      { id: 'a' }, { id: 'b' }, { id: 'c', context: true }, { id: 'd' },
    ];
    const uses: Record<string, number> = { b: 5, d: 2 };
    expect(rankByUse(items, id => uses[id] ?? 0).map(i => i.id)).toEqual(['c', 'b', 'd', 'a']);
  });

  it('counts uses and keeps them in this browser', () => {
    const uses = TestBed.inject(PaletteUses);
    uses.bump('cmd:save');
    uses.bump('cmd:save');
    expect(uses.count('cmd:save')).toBe(2);
    expect(JSON.parse(localStorage.getItem('attome.palette.uses') ?? '{}')).toEqual({ 'cmd:save': 2 });
  });
});
