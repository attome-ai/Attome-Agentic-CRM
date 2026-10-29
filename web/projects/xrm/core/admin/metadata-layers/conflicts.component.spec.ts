import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService, UserPreferencesService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { MetadataConflictsComponent, PROPOSE_CONFLICT_ACTION } from './conflicts.component';
import type { LayerConflict } from './metadata-layers.model';

const CONFLICT: LayerConflict = {
  id: 'c1', object_kind: 'attribute', object_key: 'account.name', property: 'max_length',
  old_platform: 100, new_platform: 200, customer: 150, status: 'open', resolution: null,
  resolved_by: null, resolved_at: null, created_at: '2026-10-28T08:00:00Z',
};

describe('MetadataConflictsComponent (Y11-T15)', () => {
  function create(proposal: unknown = { status: 'proposed', choice: 'combine', value: 250, reasoning: 'Keep room for both.', conflict_id: 'c1' }) {
    const getAllPages = vi.fn((_: string, _p?: Record<string, string>) => of([CONFLICT]));
    const post = vi.fn((path: string, _body: unknown) =>
      of(path.includes('/actions/') ? { status: 'completed', result: proposal } : { ...CONFLICT, status: 'resolved' }));
    TestBed.configureTestingModule({
      imports: [MetadataConflictsComponent],
      providers: [
        { provide: ApiService, useValue: { getAllPages, post } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => 'UTC', calendar: () => null, digits: () => null } },
      ],
    });
    const fixture = TestBed.createComponent(MetadataConflictsComponent);
    fixture.detectChanges();
    return { fixture, getAllPages, post };
  }

  it('lists the open conflicts', () => {
    const { fixture, getAllPages } = create();
    expect(getAllPages).toHaveBeenCalledWith('/api/v1/admin/metadata/conflicts', { status: 'open' });
    const card = fixture.nativeElement.querySelector('article[data-conflict="c1"]') as HTMLElement;
    expect(card.textContent).toContain('account.name');
    expect(card.textContent).toContain('150');
  });

  it('conflict resolve sends choice', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.resolve(CONFLICT, 'keep_customer');
    expect(post).toHaveBeenCalledWith('/api/v1/admin/metadata/conflicts/c1/resolve', { choice: 'keep_customer' });

    c.startCombine(CONFLICT, null);
    c.combined.set('180');
    c.resolve(CONFLICT, 'combine');
    expect(post).toHaveBeenLastCalledWith('/api/v1/admin/metadata/conflicts/c1/resolve', { choice: 'combine', value: 180 });
  });

  it('refuses a combined value that is not JSON', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.startCombine(CONFLICT, null);
    c.combined.set('{not json');
    c.resolve(CONFLICT, 'combine');
    expect(post).not.toHaveBeenCalled();
    expect(c.badJson()).toBe(true);
  });

  it("shows the agent's proposal and resolves nothing until a click", () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.ask(CONFLICT);
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith(`/api/v1/actions/${PROPOSE_CONFLICT_ACTION}/invoke`, { args: { conflict_id: 'c1' } });
    expect(post).toHaveBeenCalledTimes(1);
    expect(fixture.nativeElement.textContent).toContain('Keep room for both.');

    // Using a combine proposal opens its value for checking; still no resolve.
    const proposal = c.proposals()['c1'];
    if (proposal.status !== 'proposed') throw new Error('expected a proposal');
    c.useProposal(CONFLICT, proposal);
    expect(post).toHaveBeenCalledTimes(1);
    expect(c.combining()).toBe('c1');
    expect(c.combined()).toBe('250');
  });
});
