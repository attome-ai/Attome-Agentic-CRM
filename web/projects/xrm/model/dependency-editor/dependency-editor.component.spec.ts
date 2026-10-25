import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ApiService, LangService } from '@attome/base';
import { ModelService } from '../model.service';
import { DependencyEditorComponent, isAllowed, toggleCell } from './dependency-editor.component';

describe('DependencyEditorComponent (A6-T4)', () => {
  it('toggles cells and drops an emptied row', () => {
    let m: Record<string, string[]> = {};
    m = toggleCell(m, 'central', 'riyadh');
    m = toggleCell(m, 'central', 'kharj');
    expect(m).toEqual({ central: ['riyadh', 'kharj'] });
    expect(isAllowed(m, 'central', 'kharj')).toBe(true);
    m = toggleCell(m, 'central', 'riyadh');
    m = toggleCell(m, 'central', 'kharj');
    expect(m).toEqual({});
  });

  function create() {
    const model = {
      objects: vi.fn().mockReturnValue(of({ items: [], total: 0, page: 1, page_size: 50 })),
      object: vi.fn(),
      saveDraft: vi.fn().mockReturnValue(of({ id: 'd1', version_no: 1, content_hash: 'h1', issues: [] })),
      publish: vi.fn().mockReturnValue(of({ id: 'd1', version_no: 1 })),
    };
    const get = vi.fn((path: string) => path.startsWith('/api/v1/schema/')
      ? of({ fields: [
          { name: 'region', field_type: 'choice', options: { choices: ['central', 'western'] } },
          { name: 'city', field_type: 'choice', options: { choices: ['riyadh', 'jeddah'] } },
          { name: 'notes', field_type: 'text', options: null },
        ] })
      : of({ count: 3, sample_ids: ['a', 'b', 'c'] }));
    TestBed.configureTestingModule({
      imports: [DependencyEditorComponent],
      providers: [
        { provide: ModelService, useValue: model },
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(DependencyEditorComponent);
    fixture.detectChanges();
    return { fixture, model, get };
  }

  it('builds the matrix from the attributes\' choices, saves it and checks the impact', () => {
    const { fixture, model, get } = create();
    const editor = fixture.componentInstance;
    editor.startNew();
    editor.name.set('city_by_region');
    editor.entity.set('account');
    editor.loadSchema();
    expect(editor.choiceFields().map(f => f.name)).toEqual(['region', 'city']);
    editor.controlling.set('region');
    editor.dependent.set('city');
    expect(editor.controllingValues()).toEqual(['central', 'western']);
    expect(editor.dependentValues()).toEqual(['riyadh', 'jeddah']);
    expect(editor.ready()).toBe(false);
    editor.toggle('central', 'riyadh');
    expect(editor.ready()).toBe(true);

    editor.save();
    const [kind, , base, name, commands] = model.saveDraft.mock.calls[0];
    expect(kind).toBe('dependency');
    expect(base).toBe('');
    expect(name).toBe('city_by_region');
    expect(commands).toContainEqual({ op: 'set', path: '/matrix', value: { central: ['riyadh'] } });
    expect(editor.hash()).toBe('h1');

    editor.checkImpact();
    expect(get).toHaveBeenLastCalledWith(expect.stringMatching(/\/api\/v1\/admin\/model\/dependency\/.+\/impact$/));
    expect(editor.impact()?.count).toBe(3);
  });
});
