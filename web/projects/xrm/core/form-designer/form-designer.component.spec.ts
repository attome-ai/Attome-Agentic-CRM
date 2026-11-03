import { TestBed } from '@angular/core/testing';
import { LangService, SdkService } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { LiveService, ModelService } from '@attome/xrm/model';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { FormDesignerComponent } from './form-designer.component';
import { FIELD_BUDGET, checkForm, fromDesign, previewFieldType, toDesign } from './form-doc';
import type { FormDoc } from './form-doc';

const TABBED: FormDoc = {
  entity: 'e1', form_kind: 'main',
  tabs: [
    { label: 'General', sections: [{ label: 'Main', columns: 2, fields: ['a1', 'a2'], related: [{ entity: 'e2', label: 'Cases' }] }] },
    { label: 'More', sections: [{ label: 'Notes', fields: ['a3'] }] },
  ],
  targeting: { stages: ['qualify'] },
};

describe('form document and canvas tree (A12-T3)', () => {
  it('round-trips a tabbed form through the canvas tree', () => {
    const design = toDesign(TABBED);
    expect(design.root.children?.map(n => n.type)).toEqual(['tab', 'tab']);
    expect(design.root.children?.[0].children?.[0].props).toEqual({ label: 'Main', columns: 2 });
    const { doc, misplaced } = fromDesign(design, TABBED);
    expect(misplaced).toBe(0);
    expect(doc).toEqual(TABBED);
  });

  it('round-trips a form with sections only, and leaves out a misplaced field', () => {
    const flat: FormDoc = { entity: 'e1', sections: [{ label: 'Main', fields: ['a1'] }] };
    const design = toDesign(flat);
    expect(fromDesign(design, flat).doc).toEqual({ entity: 'e1', sections: [{ label: 'Main', fields: ['a1'] }] });
    design.root.children?.push({ type: 'field', attribute: 'a2' });
    const out = fromDesign(design, flat);
    expect(out.misplaced).toBe(1);
    expect(out.doc.sections?.[0].fields).toEqual(['a1']);
  });

  it('checks labels, unknown and repeated fields, and size', () => {
    const names = new Map([['a1', 'Name'], ['a2', 'Email']]);
    const doc: FormDoc = { entity: 'e1', sections: [{ label: ' ', fields: ['a1', 'a1', 'zz'] }] };
    expect(checkForm(doc, names, 0).map(c => c.key)).toEqual(['sectionLabel', 'twice', 'unknownField']);
    const fields = Array.from({ length: FIELD_BUDGET + 1 }, (_, i) => `f${i}`);
    const big: FormDoc = { entity: 'e1', sections: [{ label: 'All', fields }] };
    const many = new Map(fields.map(f => [f, f] as const));
    expect(checkForm(big, many, 0).map(c => c.key)).toEqual(['tooManyFields']);
  });

  it('previews each attribute type with the renderer\'s control', () => {
    expect(previewFieldType('currency')).toBe(1);
    expect(previewFieldType('date_time')).toBe(5);
    expect(previewFieldType('bool')).toBe(6);
    expect(previewFieldType('lookup')).toBe(11);
    expect(previewFieldType('text')).toBe(3);
  });
});

describe('FormDesignerComponent (A12-T3)', () => {
  let model: Record<string, ReturnType<typeof vi.fn>>;

  beforeEach(() => {
    model = {
      object: vi.fn().mockReturnValue(of({
        id: 'f1', kind: 'form', name: 'Contact form', version_no: 1, kind_schema_version: 1, state: 'draft',
        content_hash: 'h1', doc: { entity: 'e1', sections: [{ label: 'Main', fields: ['a1'] }] },
      })),
      saveDraft: vi.fn().mockReturnValue(of({ id: 'f1', version_no: 2, content_hash: 'h2', issues: [] })),
      publish: vi.fn().mockReturnValue(of({ id: 'f1', version_no: 2 })),
      schema: vi.fn().mockReturnValue(of({ fields: [], business_rules: [] })),
      formHooks: vi.fn().mockReturnValue(of({ changes: {}, rejection: null, rejection_translations: {}, events: [] })),
    };
    const entity = {
      id: 'e1', logicalname: 'contact', attributes: [
        { id: 'a1', logicalname: 'full_name', name: 'Full name', field_type: 'text', is_required: true, is_active: true },
        { id: 'a2', logicalname: 'email', name: 'Email', field_type: 'text', is_required: false, is_active: true },
      ],
    };
    TestBed.configureTestingModule({
      imports: [FormDesignerComponent],
      providers: [
        { provide: ModelService, useValue: model },
        { provide: AdminService, useValue: { getEntity: vi.fn().mockReturnValue(of(entity)) } },
        { provide: SdkService, useValue: {} },
        { provide: LiveService, useValue: { connect: vi.fn() } },
        { provide: LangService, useValue: { translate: (key: string) => key, errorText: () => 'error', current: () => 'en' } },
      ],
    });
  });

  function render(id = 'f1', entity: string | null = null) {
    const fixture = TestBed.createComponent(FormDesignerComponent);
    fixture.componentRef.setInput('id', id);
    fixture.componentRef.setInput('entity', entity);
    fixture.detectChanges();
    return fixture;
  }

  it('offers the fields not yet on the form and adds one into the section', () => {
    const fixture = render();
    const cmp = fixture.componentInstance;
    expect(cmp.available().map(a => a.logicalname)).toEqual(['email']);
    cmp.addField(cmp.available()[0]);
    fixture.detectChanges();
    expect(cmp.draft()?.doc.sections?.[0].fields).toEqual(['a1', 'a2']);
    expect(cmp.available()).toEqual([]);
    expect(cmp.previewPlan()?.sections[0].fields.map(f => f.attribute)).toEqual(['full_name', 'email']);
  });

  it('turns the sections into a first tab, and saves the tabs against the draft\'s hash', () => {
    const fixture = render();
    const cmp = fixture.componentInstance;
    cmp.addTab();
    fixture.detectChanges();
    expect(cmp.draft()?.doc.tabs?.[0].sections[0].fields).toEqual(['a1']);
    cmp.save();
    expect(model['saveDraft']).toHaveBeenCalledWith('form', 'f1', 'h1', null, [
      { op: 'set', path: '/tabs', value: [{ label: 'formDesigner.newTab', sections: [{ label: 'Main', fields: ['a1'] }] }] },
      { op: 'remove', path: '/sections' },
    ]);
    expect(cmp.saved()).toBe(2);
  });

  it('starts a new form for the entity when none exists', () => {
    model['object'].mockReturnValue(throwError(() => ({ status: 404 })));
    const fixture = render('f9', 'e1');
    const cmp = fixture.componentInstance;
    expect(cmp.draft()?.doc).toEqual({
      entity: 'e1', form_kind: 'main', sections: [{ label: 'formDesigner.newSection', fields: [] }],
    });
    cmp.save();
    expect(model['saveDraft']).toHaveBeenCalledWith('form', 'f9', '', 'form', [
      { op: 'set', path: '/entity', value: 'e1' },
      { op: 'set', path: '/form_kind', value: 'main' },
      { op: 'set', path: '/sections', value: [{ label: 'formDesigner.newSection', fields: [] }] },
    ]);
  });
});
