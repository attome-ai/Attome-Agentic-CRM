import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { SdkService, AuthService, ChangesetState, LangService, type ApiError } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import { type ChangesetSummary } from '@attome/xrm/core/admin/data';
import { of, throwError, type Observable } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { ChangesetIndicatorComponent } from './changeset-indicator.component';
import { sdkFromApi } from '../../testing/sdk-from-api';

function changeset(id: string, layer: string, author_ref: string | null, title = id): ChangesetSummary {
  return {
    id, layer, title, name: id, scope: 'core', description: '', origin: 'authored', status: 'open',
    requires: {}, op_count: 2, author_ref, author_label: 'Dev', opened_at: '2026-09-29T00:00:00Z', row_version: 1,
  };
}

function mount(opts: { admin: boolean; list: () => Observable<unknown> }) {
  const picked = signal<string | null>(null);
  // The pick lives in ChangesetState (Y9-T3); `api.setChangeset` is its setter here.
  const state = { active: picked.asReadonly(), set: vi.fn((id: string | null) => picked.set(id)) };
  const api = {
    get: vi.fn(opts.list),
    setChangeset: state.set,
  };
  TestBed.configureTestingModule({
    providers: [
      { provide: SdkService, useValue: sdkFromApi(api) },
      { provide: ChangesetState, useValue: state },
      { provide: AuthService, useValue: { userId: signal('me') } },
      { provide: AccessService, useValue: { ready: () => of(undefined), hasPrivilege: () => opts.admin } },
      { provide: LangService, useValue: {
        translate: (k: string, p?: Record<string, unknown>) => (p ? `${k}${JSON.stringify(p)}` : k),
      } },
    ],
  });
  const fixture = TestBed.createComponent(ChangesetIndicatorComponent);
  fixture.detectChanges();
  return { fixture, api, el: fixture.nativeElement as HTMLElement };
}

const page = (items: ChangesetSummary[]) => () => of({ items, total: items.length, page: 1, page_size: 100 });

describe('ChangesetIndicatorComponent', () => {
  it('never asks, and renders nothing, for a non-admin', () => {
    const { api, el } = mount({ admin: false, list: page([]) });
    expect(api.get).not.toHaveBeenCalled();
    expect(el.textContent?.trim()).toBe('');
  });

  it('stays hidden when production refuses the authoring route', () => {
    const locked: ApiError = { status: 403, kind: 'authoring_locked', message: '' };
    const { api, el } = mount({ admin: true, list: () => throwError(() => locked) });
    expect(api.get).toHaveBeenCalledWith('/api/v1/admin/changesets', { status: 'open', page: '1', page_size: '100' });
    expect(el.querySelector('.cs-indicator')).toBeNull();
  });

  it('says so when nothing is open', () => {
    const { el } = mount({ admin: true, list: page([]) });
    expect(el.querySelector('.cs-indicator')?.textContent).toContain('changesets.indicator.noneOpen');
    expect(el.querySelector('select')).toBeNull();
  });

  it("lists open changesets, names the caller's own as the fallback, and picks one", () => {
    const { fixture, api, el } = mount({
      admin: true,
      list: page([changeset('a', 'platform', 'someone-else', 'Platform work'), changeset('b', 'project', 'me', 'My work')]),
    });
    const select = el.querySelector('select')!;
    const label = el.querySelector(`label[for="${select.id}"]`);
    expect(label?.textContent).toContain('changesets.indicator.pick');
    const options = Array.from(select.options).map(o => o.textContent?.trim());
    expect(options[0]).toContain('changesets.indicator.yours');
    expect(options[0]).toContain('My work');
    expect(options[1]).toContain('Platform work');
    expect(options[1]).toContain('changesets.layer.platform');

    select.value = 'a';
    select.dispatchEvent(new Event('change'));
    fixture.detectChanges();
    expect(api.setChangeset).toHaveBeenCalledWith('a');

    select.value = '';
    select.dispatchEvent(new Event('change'));
    expect(api.setChangeset).toHaveBeenLastCalledWith(null);
  });

  it('shows a load failure as an alert', () => {
    const boom: ApiError = { status: 500, kind: 'internal', message: '' };
    const { el } = mount({ admin: true, list: () => throwError(() => boom) });
    expect(el.querySelector('[role="alert"]')?.textContent).toContain('changesets.indicator.error');
  });
});
