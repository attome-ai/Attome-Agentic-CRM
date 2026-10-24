import { TestBed } from '@angular/core/testing';
import { EMPTY, of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { AdminService, DataProfileService, type AttributeMeta } from '@attome/xrm/core/admin/data';
import { EntityEditorComponent, renderFormat } from './entity-editor.component';

describe('EntityEditorComponent route input', () => {
  const getEntity = vi.fn(() => EMPTY);

  beforeEach(() => {
    getEntity.mockClear();
    TestBed.configureTestingModule({
      imports: [EntityEditorComponent],
      providers: [
        { provide: AdminService, useValue: { getEntity } },
        { provide: DataProfileService, useValue: { latest: () => of(null) } },
        // C-29 (M01 §7) — `typeLabel()` now injects the real `LangService`
        // (i18n-driven field-type labels instead of a hardcoded English
        // map); the stub echoes the key, same pattern every other spec that
        // injects LangService uses (FE-2).
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    TestBed.overrideComponent(EntityEditorComponent, { set: { template: '' } });
  });

  // The route moved from /xrm/admin/entities/:id to /xrm/admin/entity?id=…;
  // withComponentInputBinding() feeds both shapes into the same input, so this
  // assertion holds across the rename and is what makes it a safe one.
  it('loads the entity identified by the route-bound id input', () => {
    const fixture = TestBed.createComponent(EntityEditorComponent);
    fixture.componentRef.setInput('id', 'entity-1');

    fixture.detectChanges();

    expect(getEntity).toHaveBeenCalledWith('entity-1');
  });
});

// Solution 7 Phase 2 (D-788) — the field structure-change dialog is opened
// from a field card and reloads the entity only when a change was applied.
describe('EntityEditorComponent field changes', () => {
  const getEntity = vi.fn();

  beforeEach(() => {
    getEntity.mockReset();
    getEntity.mockReturnValue(of({ id: 'entity-1', logicalname: 'contact', name: 'Contact', attributes: [] }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [EntityEditorComponent],
      providers: [
        { provide: AdminService, useValue: { getEntity } },
        { provide: DataProfileService, useValue: { latest: () => of(null) } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    TestBed.overrideComponent(EntityEditorComponent, { set: { template: '' } });
  });

  it('opens the dialog for a field and reloads after an applied change', () => {
    const fixture = TestBed.createComponent(EntityEditorComponent);
    fixture.componentRef.setInput('id', 'entity-1');
    fixture.detectChanges();
    const cmp = fixture.componentInstance;
    const field = { id: 'f1', logicalname: 'rating', name: 'Rating', field_type: 'text' } as AttributeMeta;

    cmp.openFieldChange(field, 'delete');
    expect(cmp.dialogField()).toBe(field);
    expect(cmp.dialogMode()).toBe('delete');

    cmp.onFieldChangeClosed(false);
    expect(cmp.dialogField()).toBeNull();
    expect(getEntity).toHaveBeenCalledTimes(1);

    cmp.openFieldChange(field, 'rename');
    cmp.onFieldChangeClosed(true);
    expect(getEntity).toHaveBeenCalledTimes(2);
  });
});

// Cross-language contract: these are the same cases attome-metadata's autovalue.rs
// asserts for `render_format`. The preview is presentation-only, but an admin
// who sees AVG-0001-26-08-07 here and gets something else on the record has
// been actively misled — so the two implementations are pinned to each other.
describe('renderFormat (mirror of autovalue.rs render_format)', () => {
  // 2026-08-07T13:04:05Z — the same instant the Rust tests use.
  const at = new Date(Date.UTC(2026, 7, 7, 13, 4, 5));

  it('renders the motivating example', () => {
    expect(renderFormat('AVG-{DDDD}-{YY-MM-DD}', 1, at)).toBe('AVG-0001-26-08-07');
  });

  it('pads the sequence to the token width and overflows rather than truncating', () => {
    expect(renderFormat('{DD}', 7, at)).toBe('07');
    expect(renderFormat('{####}', 42, at)).toBe('0042');
    expect(renderFormat('{SEQ:6}', 42, at)).toBe('000042');
    expect(renderFormat('{SEQ}', 42, at)).toBe('42');
    expect(renderFormat('{DDD}', 123456, at)).toBe('123456');
  });

  it('renders date pattern units and passes literals through', () => {
    expect(renderFormat('{YYYY}', 1, at)).toBe('2026');
    expect(renderFormat('{YYYY/MM/DD}', 1, at)).toBe('2026/08/07');
    // MM is month, mm is minute.
    expect(renderFormat('{HH:mm:ss}', 1, at)).toBe('13:04:05');
    expect(renderFormat('{MM}-{mm}', 1, at)).toBe('08-04');
  });

  it('keeps literal text, escaped braces, and an unterminated brace', () => {
    expect(renderFormat('INV', 1, at)).toBe('INV');
    expect(renderFormat('{{x}}', 1, at)).toBe('{x}');
    // A typo must not swallow the rest of the format.
    expect(renderFormat('A-{DDD', 1, at)).toBe('A-{DDD');
  });
});
