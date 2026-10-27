import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideRouter, Router } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { ModelService } from '@attome/xrm/model';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AppDesignerComponent } from './app-designer.component';
import { Navigation, navProblems, navigationOf, saveCommands, toCanvas, uuidv7 } from './app-design.model';

const FORM = '0190f5a4-0000-7000-8000-00000000000a';
const VIEW = '0190f5a4-0000-7000-8000-00000000000b';

describe('AppDesignerComponent (A21-T3)', () => {
  const stored: Navigation = {
    groups: [{ label: 'Sales', items: [
      { label: 'Accounts', kind: 'form', target: FORM, roles: ['0190f5a4-0000-7000-8000-0000000000aa'] },
      { label: 'Help', kind: 'url', url: 'https://acme.sa/help' },
    ] }],
    landing: [{ role: '0190f5a4-0000-7000-8000-0000000000aa', item: 'Sales/Accounts' }],
    settings: { name: 'Sales app', languages: ['ar', 'en'] },
  };

  function setUp(id: string) {
    const model = {
      object: vi.fn(() => of({ id: 'nav-1', kind: 'navigation', name: 'Sales', version_no: 2, kind_schema_version: 1,
        state: 'draft', doc: stored, content_hash: 'h1', created_at: '' })),
      objects: vi.fn((kind: string) => of({ items: kind === 'form'
        ? [{ id: FORM, name: 'Account form', app: '', owner_layer: 'customer', version_no: 1, state: 'published', content_hash: '' }]
        : [], total: 0, page: 1, page_size: 50 })),
      saveDraft: vi.fn(() => of({ id: 'nav-1', version_no: 3, content_hash: 'h2', issues: [] })),
      publish: vi.fn(() => of({ id: 'nav-1', version_no: 3 })),
    };
    const api = { get: vi.fn(() => of({ items: [{ target_kind: 'entity', target_name: 'account' }] })) };
    TestBed.configureTestingModule({
      imports: [AppDesignerComponent],
      providers: [
        provideRouter([]),
        { provide: ModelService, useValue: model },
        { provide: ApiService, useValue: api },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
            errorText: () => 'error',
            current: signal('en'),
            intlLocale: signal('en-US'),
          },
        },
      ],
    });
    vi.spyOn(TestBed.inject(Router), 'navigate').mockResolvedValue(true);
    const fixture = TestBed.createComponent(AppDesignerComponent);
    fixture.componentRef.setInput('id', id);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement, model, api };
  }

  it('opens a saved app on the canvas with its settings', () => {
    const { cmp, el } = setUp('nav-1');
    expect(cmp.groups()).toEqual(stored.groups);
    expect(el.querySelectorAll('[data-testid="canvas-node"]').length).toBe(4);
    expect((el.querySelector('[data-setting-name]') as HTMLInputElement).value).toBe('Sales app');
    expect((el.querySelector('[data-lang-ar]') as HTMLInputElement).checked).toBe(true);
  });

  it('adds a picked form to the selected group and saves the whole menu', () => {
    const { fixture, cmp, el, model } = setUp('nav-1');
    cmp.onSelect(['/root/children/0']);
    (el.querySelector(`[data-source="${FORM}"]`) as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(cmp.groups()[0].items.at(-1)).toEqual({ label: 'Account form', kind: 'form', target: FORM });
    expect(cmp.problems()).toEqual([]);
    cmp.save();
    const [kind, id, hash, name, commands] = model.saveDraft.mock.calls[0] as unknown as [string, string, string, string | null, { path: string; value?: unknown }[]];
    expect([kind, id, hash, name]).toEqual(['navigation', 'nav-1', 'h1', null]);
    expect(commands.map(c => c.path)).toEqual(['/groups', '/landing', '/settings']);
    expect((commands[0].value as Navigation['groups'])[0].items).toHaveLength(3);
  });

  it('adds a view by id and lists what the menu would be refused for', () => {
    const { fixture, cmp, el } = setUp('nav-1');
    cmp.byIdKind.set('view');
    cmp.byIdValue.set('not-an-id');
    cmp.byIdLabel.set('Pipeline');
    cmp.addById();
    fixture.detectChanges();
    expect(el.querySelector('[data-problems]')?.textContent).toContain('appDesigner.problems.noTarget {"item":"Sales/Pipeline"}');
  });

  it('simple mode hides the colours', () => {
    const { fixture, el, cmp } = setUp('nav-1');
    expect(el.querySelector('[data-advanced]')).not.toBeNull();
    cmp.setSetting({ simple: true });
    fixture.detectChanges();
    expect(el.querySelector('[data-advanced]')).toBeNull();
  });

  it('maps what each item opens and what a form reads', () => {
    const { cmp, api } = setUp('nav-1');
    cmp.mapDependencies();
    expect(api.get).toHaveBeenCalledWith(`/api/v1/admin/model/form/${FORM}/references`, { page_size: '100' });
    expect(cmp.dependencies()[0]).toEqual({ item: 'Sales/Accounts', kind: 'form', target: FORM, uses: ['entity: account'] });
    expect(cmp.dependencies()[1].uses).toEqual([]);
  });

  it('starts a new app with a first group and saves it under a fresh UUIDv7 with its name', () => {
    const { cmp, model } = setUp('new');
    expect(cmp.groups()).toHaveLength(1);
    cmp.setSetting({ name: 'Service' });
    cmp.save();
    const [, id, hash, name] = model.saveDraft.mock.calls[0] as unknown as [string, string, string, string];
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect([hash, name]).toEqual(['', 'Service']);
  });

  it('converts menus purely', () => {
    const nav = navigationOf(toCanvas(stored), stored.landing, { ...stored.settings, primary_colour: 'red' });
    expect(nav.groups).toEqual(stored.groups);
    expect(nav.settings).toEqual({ name: 'Sales app', languages: ['ar', 'en'] });
    const dropped = navigationOf(toCanvas({ groups: [] }), stored.landing, {});
    expect(dropped.landing).toBeUndefined();
    expect(saveCommands(dropped, stored)).toEqual([
      { op: 'set', path: '/groups', value: [] }, { op: 'remove', path: '/landing' }, { op: 'remove', path: '/settings' },
    ]);
    expect(navProblems([{ label: 'G', items: [{ label: 'X', kind: 'url', url: 'javascript:x' }, { label: 'V', kind: 'view', target: VIEW }] }]))
      .toEqual([{ at: 'G/X', problem: 'badUrl' }]);
    expect(uuidv7(0).startsWith('00000000-0000-7')).toBe(true);
  });
});
