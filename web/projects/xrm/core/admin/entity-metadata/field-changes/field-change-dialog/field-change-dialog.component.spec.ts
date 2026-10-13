import { ComponentFixture, TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { ConfirmService } from '@attome/base/dialog';
import { FieldChangeService, type AttributeMeta, type FieldChangeResult } from '@attome/xrm/core/admin/data';
import {
  FieldChangeDialogComponent, parseChoiceMap, splitList, type FieldChangeMode,
} from './field-change-dialog.component';

function attr(over: Partial<AttributeMeta> = {}): AttributeMeta {
  return {
    id: 'f1', entity_id: 'e1', logicalname: 'rating', name: 'Rating', field_type: 'text',
    data_classification: 'internal', is_active: true, is_filterable: false, is_required: false,
    is_sensitive: false, is_sortable: false, is_write_restricted: false, on_target_delete: 'restrict',
    owner_layer: 'customer', sort_order: 1, options: null,
    ...over,
  } as AttributeMeta;
}

function result(over: Partial<FieldChangeResult> = {}): FieldChangeResult {
  return {
    op: 'delete_field', entity: 'contact', field: 'rating', dry_run: true, applied: false,
    error: null, references: [], blockers: [], values_to_archive: 2, not_convertible: null,
    sample_record_ids: [], archived: 0, nulled: 0, records_with_value: null, run_id: null,
    report: [], labels: [], ...over,
  };
}

describe('FieldChangeDialogComponent', () => {
  let fixture: ComponentFixture<FieldChangeDialogComponent>;
  let svc: Record<string, ReturnType<typeof vi.fn>>;

  async function render(mode: FieldChangeMode, field: AttributeMeta = attr()) {
    await TestBed.configureTestingModule({
      imports: [FieldChangeDialogComponent],
      providers: [
        { provide: FieldChangeService, useValue: svc },
        { provide: ConfirmService, useValue: { confirm: vi.fn().mockResolvedValue(true) } },
        {
          provide: LangService,
          useValue: {
            translate: (key: string) => (key.startsWith('structureErrors.') ? `T:${key}` : key),
            errorText: () => 'errors.unknown', intlLocale: () => 'en-US', current: () => 'ar',
          },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(FieldChangeDialogComponent);
    fixture.componentRef.setInput('entityId', 'e1');
    fixture.componentRef.setInput('field', field);
    fixture.componentRef.setInput('mode', mode);
    fixture.detectChanges();
  }

  const el = () => fixture.nativeElement as HTMLElement;
  const btn = (id: string) => el().querySelector(`[data-testid="${id}"]`) as HTMLButtonElement;

  beforeEach(() => {
    TestBed.resetTestingModule();
    svc = {
      rename: vi.fn().mockReturnValue(of({ kind: 'result', status: 200, result: result({ op: 'rename_field' }) })),
      delete: vi.fn().mockReturnValue(of({ kind: 'result', status: 200, result: result() })),
      changeType: vi.fn().mockReturnValue(of({ kind: 'result', status: 200, result: result({ op: 'change_field_type', not_convertible: 1 }) })),
      addChoice: vi.fn().mockReturnValue(of({ kind: 'result', status: 200, result: result({ op: 'add_choice_value', dry_run: false, applied: true }) })),
      removeChoice: vi.fn().mockReturnValue(of({ kind: 'result', status: 200, result: result({ op: 'remove_choice_value', records_with_value: 3 }) })),
      abandonRun: vi.fn(),
    };
  });

  it('is a labelled modal dialog', async () => {
    await render('rename');
    const dialog = el().querySelector('[role="dialog"]')!;
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(dialog.getAttribute('aria-labelledby')).toBe('fcd-title');
  });

  it('refuses an invalid or unchanged name before calling the server', async () => {
    await render('rename');
    expect(btn('apply').disabled).toBe(true); // same name
    fixture.componentInstance.newName.set('Bad Name');
    fixture.detectChanges();
    expect(btn('apply').disabled).toBe(true);
    expect(el().textContent).toContain('fieldChange.rename.invalid');
    fixture.componentInstance.newName.set('rating_level');
    fixture.detectChanges();
    expect(btn('apply').disabled).toBe(false);
  });

  it('checks and then renames', async () => {
    await render('rename');
    fixture.componentInstance.newName.set('rating_level');
    fixture.componentInstance.checkRename();
    expect(svc['rename']).toHaveBeenCalledWith('e1', 'f1', 'rating_level', true);
    svc['rename'].mockReturnValue(of({ kind: 'result', status: 200, result: result({ op: 'rename_field', dry_run: false, applied: true }) }));
    fixture.componentInstance.applyRename();
    expect(svc['rename']).toHaveBeenLastCalledWith('e1', 'f1', 'rating_level', false);
    expect(fixture.componentInstance.changed()).toBe(true);
  });

  it('loads the delete preview on open and needs the tick to delete', async () => {
    await render('delete');
    expect(svc['delete']).toHaveBeenCalledWith('e1', 'f1', true);
    expect(el().querySelector('attome-field-change-result')).not.toBeNull();
    expect(btn('apply').disabled).toBe(true);
    fixture.componentInstance.deleteConfirmed.set(true);
    fixture.detectChanges();
    expect(btn('apply').disabled).toBe(false);
    fixture.componentInstance.applyDelete();
    expect(svc['delete']).toHaveBeenLastCalledWith('e1', 'f1', false);
  });

  it('cannot delete when the preview is blocked', async () => {
    svc['delete'].mockReturnValue(of({ kind: 'result', status: 409, result: result({ error: 'field_referenced' }) }));
    await render('delete');
    fixture.componentInstance.deleteConfirmed.set(true);
    fixture.detectChanges();
    expect(fixture.componentInstance.deleteReady()).toBe(false);
    expect(btn('apply').disabled).toBe(true);
  });

  it('shows the background run of a large delete', async () => {
    svc['delete'].mockReturnValue(of({ kind: 'result', status: 202, result: result({ dry_run: false, applied: true, run_id: 'run1' }) }));
    await render('delete');
    expect(el().querySelector('attome-field-run-status')).not.toBeNull();
  });

  it('offers only the defined conversions and sends the conversion', async () => {
    await render('changeType');
    expect(fixture.componentInstance.targets()).toContain('date');
    fixture.componentInstance.targetType.set('date');
    fixture.componentInstance.dateFormat.set('dd/mm/yyyy');
    fixture.detectChanges();
    expect(el().querySelector('#fcd-format')).not.toBeNull();
    fixture.componentInstance.checkChangeType();
    expect(svc['changeType']).toHaveBeenCalledWith('e1', 'f1', 'date', { from_type: 'text', format: 'dd/mm/yyyy' }, true);
  });

  it('needs a valid map for text to choice', async () => {
    await render('changeType');
    fixture.componentInstance.targetType.set('choice');
    expect(fixture.componentInstance.conversionIssue()).toBe('fieldChange.changeType.mapRequired');
    fixture.componentInstance.mapText.set('broken line');
    expect(fixture.componentInstance.conversionIssue()).toBe('fieldChange.changeType.mapInvalid');
    fixture.componentInstance.mapText.set('Gold = gold\nSilver = silver');
    expect(fixture.componentInstance.conversionIssue()).toBeNull();
    fixture.componentInstance.applyChangeType();
    expect(svc['changeType']).toHaveBeenCalledWith('e1', 'f1', 'choice',
      { from_type: 'text', map: { Gold: 'gold', Silver: 'silver' } }, false);
  });

  it('says a lookup cannot change type', async () => {
    await render('changeType', attr({ field_type: 'lookup' }));
    expect(el().querySelector('[data-testid="no-targets"]')).not.toBeNull();
  });

  it('adds a choice after another and shows it', async () => {
    await render('choices', attr({ field_type: 'choice', options: { choices: ['active', 'closed'] } }));
    const cmp = fixture.componentInstance;
    cmp.newChoiceValue.set('on_hold');
    cmp.newChoiceLabel.set('On hold');
    cmp.newChoiceAfter.set('active');
    cmp.addChoice();
    expect(svc['addChoice']).toHaveBeenCalledWith('e1', 'f1', { value: 'on_hold', label: 'On hold', after: 'active', locale: 'ar' });
    expect(cmp.choices()).toEqual(['active', 'on_hold', 'closed']);
  });

  it('checks how many records keep a removed choice', async () => {
    await render('choices', attr({ field_type: 'choice', options: { choices: ['active', 'closed'] } }));
    fixture.componentInstance.removeValue.set('closed');
    fixture.componentInstance.checkRemoveChoice();
    fixture.detectChanges();
    expect(svc['removeChoice']).toHaveBeenCalledWith('e1', 'f1', 'closed', true);
    expect(el().querySelector('[data-testid="records-with-value"]')).not.toBeNull();
  });

  it('shows an approval request instead of a result', async () => {
    svc['delete'].mockReturnValue(of({ kind: 'approval', approvalRequestId: 'a1' }));
    await render('delete');
    expect(el().querySelector('[data-testid="approval"]')).not.toBeNull();
  });

  it('turns a refusal into plain words', async () => {
    svc['delete'].mockReturnValue(throwError(() => ({
      kind: 'conflict', status: 409, message: 'conflict: changeset_required: open a changeset',
    })));
    await render('delete');
    expect(el().querySelector('[data-testid="dialog-error"]')?.textContent).toContain('structureErrors.changeset_required');
  });

  it('reports on close whether something changed', async () => {
    await render('rename');
    const closed = vi.fn();
    fixture.componentInstance.closed.subscribe(closed);
    btn('close').click();
    expect(closed).toHaveBeenCalledWith(false);
  });
});

describe('field change dialog helpers', () => {
  it('parses a text-to-choice map', () => {
    expect(parseChoiceMap('a = x\n\n b=y ')).toEqual({ a: 'x', b: 'y' });
    expect(parseChoiceMap('= x')).toBeNull();
    expect(parseChoiceMap('a =')).toBeNull();
    expect(parseChoiceMap('')).toEqual({});
  });

  it('splits a comma list', () => {
    expect(splitList(' yes, Y ,, true ')).toEqual(['yes', 'Y', 'true']);
  });
});
