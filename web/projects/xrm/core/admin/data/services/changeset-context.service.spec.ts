import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, AuthService, type ApiError } from '@attome/base';
import { firstValueFrom, of, throwError, type Observable } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ChangesetContextService, type ChangesetSummary } from './changeset-context.service';

function changeset(id: string, layer: string, author_ref: string | null): ChangesetSummary {
  return {
    id, layer, title: id, name: id, scope: 'core', description: '', origin: 'authored', status: 'open',
    requires: {}, op_count: 0, author_ref, author_label: 'Dev', opened_at: '2026-09-29T00:00:00Z', row_version: 1,
  };
}

function setup(list: () => Observable<unknown>, initialPick: string | null = null) {
  const picked = signal<string | null>(initialPick);
  const api = {
    get: vi.fn(list),
    activeChangeset: picked.asReadonly(),
    setChangeset: vi.fn((id: string | null) => picked.set(id)),
  };
  TestBed.configureTestingModule({
    providers: [
      { provide: ApiService, useValue: api },
      { provide: AuthService, useValue: { userId: signal('me') } },
    ],
  });
  return { svc: TestBed.inject(ChangesetContextService), api };
}

const page = (items: ChangesetSummary[]) => () => of({ items, total: items.length, page: 1, page_size: 100 });

describe('ChangesetContextService', () => {
  it('has no editing layer before anything is known', () => {
    const { svc } = setup(page([]));
    expect(svc.status()).toBe('idle');
    expect(svc.editingLayer()).toBeNull();
  });

  it("uses the caller's only open changeset when nothing is picked (the server's rule)", async () => {
    const { svc } = setup(page([changeset('a', 'platform', 'other'), changeset('b', 'product', 'me')]));
    expect(await firstValueFrom(svc.refresh())).toBe('ready');
    expect(svc.effective()?.id).toBe('b');
    expect(svc.editingLayer()).toBe('product');
  });

  it('the pick wins, and is forwarded to ApiService', async () => {
    const { svc, api } = setup(page([changeset('a', 'platform', 'other'), changeset('b', 'product', 'me')]));
    await firstValueFrom(svc.refresh());
    svc.select('a');
    expect(api.setChangeset).toHaveBeenCalledWith('a');
    expect(svc.editingLayer()).toBe('platform');
  });

  it('two of the caller\'s own open and none picked is ambiguous: no editing layer', async () => {
    const { svc } = setup(page([changeset('a', 'platform', 'me'), changeset('b', 'product', 'me')]));
    await firstValueFrom(svc.refresh());
    expect(svc.editingLayer()).toBeNull();
  });

  it('clears a pick that is no longer open', async () => {
    const { svc, api } = setup(page([changeset('b', 'product', 'me')]), 'gone');
    await firstValueFrom(svc.refresh());
    expect(api.setChangeset).toHaveBeenCalledWith(null);
  });

  it('reports the authoring gate as unavailable and anything else as an error', async () => {
    const locked: ApiError = { status: 403, kind: 'authoring_locked', message: '' };
    expect(await firstValueFrom(setup(() => throwError(() => locked)).svc.refresh())).toBe('unavailable');
    TestBed.resetTestingModule();
    const boom: ApiError = { status: 500, kind: 'internal', message: '' };
    const { svc } = setup(() => throwError(() => boom));
    expect(await firstValueFrom(svc.refresh())).toBe('error');
    expect(svc.status()).toBe('error');
  });
});
