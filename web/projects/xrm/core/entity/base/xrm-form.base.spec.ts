import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { of, Subject, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityRecord, EntitySchema } from '@attome/xrm';
import { EntityService } from '../services/entity.service';
import { RecordChangeNotifier } from '../services/record-change-notifier.service';
import { SAVED_CONFIRMATION_MS, EngineFormBase } from './xrm-form.base';

const SCHEMA: EntitySchema = {
  id: 'e1',
  name: 'User',
  logical_name: 'user_account',
  fields: [
    {
      id: 'f1', entity_id: 'e1', name: 'user_name', display_name: 'Username',
      field_type: 'text', options: null, sort_order: 0, is_required: false,
    },
    {
      id: 'f2', entity_id: 'e1', name: 'is_active', display_name: 'Is Active',
      field_type: 'bool', options: null, sort_order: 1, is_required: false,
    },
  ],
} as unknown as EntitySchema;

function record(userName: string, rowVersion: number): EntityRecord {
  return {
    id: 'rec-1',
    entity_id: 'e1',
    row_version: rowVersion,
    data: { user_name: userName, is_active: true },
  } as unknown as EntityRecord;
}

@Component({ standalone: true, template: '' })
class TestFormComponent extends EngineFormBase {}

describe('EngineFormBase — submit button state', () => {
  const navigate = vi.fn();
  let svc: {
    getSchema: ReturnType<typeof vi.fn>;
    get:       ReturnType<typeof vi.fn>;
    update:    ReturnType<typeof vi.fn>;
    create:    ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.useFakeTimers();
    navigate.mockReset();
    svc = {
      getSchema: vi.fn().mockReturnValue(of(SCHEMA)),
      get:       vi.fn().mockReturnValue(of(record('before', 3))),
      update:    vi.fn().mockReturnValue(of(record('after', 4))),
      create:    vi.fn().mockReturnValue(of(record('created', 0))),
    };
    TestBed.configureTestingModule({
      imports: [TestFormComponent],
      providers: [
        { provide: EntityService, useValue: svc },
        {
          provide: Router,
          useValue: {
            navigate,
            url: '/',
            // buildFormGroup() reads this to seed related-grid "create with
            // locked parent" query-param defaults — no query params in these tests.
            parseUrl: () => ({ queryParamMap: { get: () => null } }),
          },
        },
      ],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  function editForm() {
    const fixture = TestBed.createComponent(TestFormComponent);
    fixture.componentRef.setInput('name', 'user_account');
    fixture.componentRef.setInput('id', 'rec-1');
    fixture.detectChanges();
    return fixture;
  }

  it('disables update on a freshly loaded record and enables it once edited', () => {
    const c = editForm().componentInstance;

    expect(c.dirty()).toBe(false);
    expect(c.canSave()).toBe(false);

    // markAsDirty is what a real control does on user input; patchValue alone
    // (the load path) deliberately does not.
    c.form().get('user_name')!.markAsDirty();
    c.form().get('user_name')!.setValue('typed');

    expect(c.dirty()).toBe(true);
    expect(c.canSave()).toBe(true);
  });

  it('ignores a submit while the form is pristine', () => {
    const c = editForm().componentInstance;

    c.save();

    expect(svc.update).not.toHaveBeenCalled();
  });

  it('stays on the record after an update, confirms, and re-arms on the next edit', () => {
    const c = editForm().componentInstance;
    const control = c.form().get('user_name')!;
    control.markAsDirty();
    control.setValue('typed');

    c.save();

    expect(svc.update).toHaveBeenCalledOnce();
    expect(navigate).not.toHaveBeenCalled();
    expect(c.justSaved()).toBe(true);
    expect(c.dirty()).toBe(false);
    expect(c.canSave()).toBe(false);
    // Patched from the response, so the next If-Match carries row_version 4.
    expect(control.value).toBe('after');

    control.markAsDirty();
    control.setValue('typed again');

    expect(c.justSaved()).toBe(false);
    expect(c.canSave()).toBe(true);
  });

  it('drops the tick back to the idle button a few seconds after the save', () => {
    const c = editForm().componentInstance;
    const control = c.form().get('user_name')!;
    control.markAsDirty();
    control.setValue('typed');

    c.save();
    expect(c.justSaved()).toBe(true);

    vi.advanceTimersByTime(SAVED_CONFIRMATION_MS - 1);
    expect(c.justSaved()).toBe(true);

    vi.advanceTimersByTime(1);
    expect(c.justSaved()).toBe(false);
    // Back to "Update", still disabled — a pristine record has nothing to save.
    expect(c.canSave()).toBe(false);
  });

  it('does not leave a pending tick timer behind when the form is destroyed', () => {
    const fixture = editForm();
    const c = fixture.componentInstance;
    const control = c.form().get('user_name')!;
    control.markAsDirty();
    control.setValue('typed');
    c.save();

    fixture.destroy();

    expect(vi.getTimerCount()).toBe(0);
  });

  it('does not patch a destroyed form when the record request resolves after destroy', () => {
    // A Subject, not `of(...)`, so the GET is still in flight when we destroy
    // — the regression this covers is a navigate-away-mid-load race: without
    // `takeUntilDestroyed`, loadRecord()'s subscription outlives the
    // component and patches a form that no longer exists.
    const pending = new Subject<EntityRecord>();
    svc.get.mockReturnValue(pending.asObservable());

    const fixture = editForm();
    const c = fixture.componentInstance;
    const patchSpy = vi.spyOn(c.form(), 'patchValue');

    fixture.destroy();
    pending.next(record('arrived-after-destroy', 9));

    expect(patchSpy).not.toHaveBeenCalled();
  });

  it('sends the row_version the server returned on a second consecutive save', () => {
    const c = editForm().componentInstance;
    const control = c.form().get('user_name')!;

    control.markAsDirty();
    control.setValue('one');
    c.save();
    control.markAsDirty();
    control.setValue('two');
    c.save();

    expect(svc.update).toHaveBeenCalledTimes(2);
    expect(svc.update.mock.calls[0][3]).toBe(3);
    expect(svc.update.mock.calls[1][3]).toBe(4);
  });

  // ── A16-T3: conflicts ────────────────────────────────────────────────────

  it('sends only the changed attributes, asking the server to merge', () => {
    const c = editForm().componentInstance;
    const control = c.form().get('user_name')!;
    control.markAsDirty();
    control.setValue('typed');

    c.save();

    expect(svc.update).toHaveBeenCalledWith('user_account', 'rec-1', { user_name: 'typed' }, 3, { mergeAttributes: true });
  });

  function conflictOn(version: number) {
    return {
      kind: 'version_conflict', status: 409, message: '',
      versionConflict: {
        currentVersion: version, lastChangedBy: 'Sara', lastChangedAt: null,
        changedAttributes: [{ name: 'user_name', their_value: 'theirs', changed_by: 'Sara', changed_at: null }],
        hiddenChanges: 0,
      },
    };
  }

  it('keeps the typed values on a 409 and lists what changed', () => {
    const c = editForm().componentInstance;
    svc.update.mockReturnValueOnce(throwError(() => conflictOn(5)));
    const control = c.form().get('user_name')!;
    control.markAsDirty();
    control.setValue('typed');

    c.save();

    expect(c.conflict()).toBe(true);
    expect(c.conflictDetails()?.currentVersion).toBe(5);
    expect(c.conflictDetails()?.changedAttributes.map(a => a.name)).toEqual(['user_name']);
    expect(control.value).toBe('typed');

    c.dismissConflict();
    expect(c.conflictDetails()).toBeNull();
    expect(control.value).toBe('typed');
  });

  it('saves again at the newer version with "keep mine"', () => {
    const c = editForm().componentInstance;
    svc.update.mockReturnValueOnce(throwError(() => conflictOn(5)));
    const control = c.form().get('user_name')!;
    control.markAsDirty();
    control.setValue('typed');
    c.save();

    c.resolveConflict({ user_name: 'mine' });

    expect(svc.update).toHaveBeenCalledTimes(2);
    expect(svc.update.mock.calls[1][2]).toEqual({ user_name: 'typed' });
    expect(svc.update.mock.calls[1][3]).toBe(5);
    expect(c.conflictDetails()).toBeNull();
  });

  it('leaves an attribute to the other writer with "take theirs" and then shows their value', () => {
    const c = editForm().componentInstance;
    svc.update.mockReturnValueOnce(throwError(() => conflictOn(5)));
    svc.update.mockReturnValueOnce(of(record('theirs', 6)));
    const control = c.form().get('user_name')!;
    control.markAsDirty();
    control.setValue('typed');
    c.save();

    c.resolveConflict({ user_name: 'theirs' });

    const sent = svc.update.mock.calls[1][2] as Record<string, unknown>;
    expect(sent).not.toHaveProperty('user_name');
    expect(control.value).toBe('theirs');
  });

  it('names the attributes a save was merged over', () => {
    const c = editForm().componentInstance;
    svc.update.mockReturnValueOnce(of({ ...record('after', 4), merged_over: ['is_active'] }));
    const control = c.form().get('user_name')!;
    control.markAsDirty();
    control.setValue('typed');

    c.save();

    expect(c.mergedOver()).toEqual(['is_active']);
    control.markAsDirty();
    control.setValue('again');
    c.save();
    expect(c.mergedOver()).toEqual([]);
  });

  it('re-reads the record when a widget changes it on the server (U18), so the next save carries the new row_version', () => {
    const c = editForm().componentInstance;
    c.form().get('is_active')!.markAsDirty();
    c.form().get('is_active')!.setValue(false);
    svc.get.mockReturnValue(of(record('restored', 7)));

    TestBed.inject(RecordChangeNotifier).notify({
      entityName: 'user_account', recordId: 'rec-1', fields: ['user_name'],
    });

    expect(c.form().get('user_name')!.value).toBe('restored');
    // The operator's other unsaved edit survives, and the form stays dirty for it.
    expect(c.form().get('is_active')!.value).toBe(false);
    expect(c.dirty()).toBe(true);
    c.save();
    expect(svc.update.mock.calls.at(-1)![3]).toBe(7);
  });

  it('ignores record changes for another record or entity', () => {
    editForm();
    const calls = svc.get.mock.calls.length;
    const notifier = TestBed.inject(RecordChangeNotifier);
    notifier.notify({ entityName: 'user_account', recordId: 'other', fields: ['user_name'] });
    notifier.notify({ entityName: 'contact', recordId: 'rec-1', fields: ['user_name'] });
    expect(svc.get.mock.calls.length).toBe(calls);
  });

  it('switches to the new record\'s own form after a create, and does not gate it on dirty', () => {
    const fixture = TestBed.createComponent(TestFormComponent);
    fixture.componentRef.setInput('name', 'user_account');
    fixture.detectChanges();
    const c = fixture.componentInstance;

    expect(c.canSave()).toBe(true);

    c.save();

    expect(svc.create).toHaveBeenCalledOnce();
    expect(navigate).toHaveBeenCalledWith(
      ['/xrm', 'entity', 'user_account', 'form'],
      { queryParams: { id: 'rec-1' } },
    );
  });
});

// D-789 section 5 / D-791 rule 6 — business-rule policies applied live.
describe('EngineFormBase — business rules (D-789)', () => {
  const RULE_SCHEMA = {
    id: 'e2',
    name: 'Deal',
    plural_name: 'Deals',
    relationships: [],
    fields: [
      {
        id: 'd1', entity_id: 'e2', name: 'status', display_name: 'Status',
        field_type: 'choice', options: { choices: ['open', 'closed'], multi: false },
        sort_order: 0, is_required: false,
      },
      {
        id: 'd2', entity_id: 'e2', name: 'amount', display_name: 'Amount',
        field_type: 'number', options: null, sort_order: 1, is_required: true,
      },
      {
        id: 'd3', entity_id: 'e2', name: 'notes', display_name: 'Notes',
        field_type: 'text', options: null, sort_order: 2, is_required: false,
      },
    ],
    business_rules: [
      {
        name: 'closed_lock', display_name: 'Closed deals',
        condition: { field: 'status', op: 'eq', value: 'closed' },
        policies: [{ type: 'disabled', field: 'amount' }, { type: 'disabled', field: 'notes' }],
      },
      {
        name: 'closed_hide', display_name: null,
        condition: { field: 'status', op: 'eq', value: 'closed' },
        policies: [{ type: 'hidden', field: 'notes' }],
      },
      {
        name: 'big', display_name: 'Big deals',
        condition: { field: 'amount', op: 'gt', value: 1000 },
        policies: [{ type: 'error', field: 'amount', message: 'Needs approval', severity: 'warning' }],
      },
    ],
  } as unknown as EntitySchema;

  const stored = {
    id: 'deal-1', entity_id: 'e2', row_version: 7,
    data: { status: 'open', amount: 500, notes: 'n' },
  } as unknown as EntityRecord;

  let svc: {
    getSchema: ReturnType<typeof vi.fn>;
    get:       ReturnType<typeof vi.fn>;
    update:    ReturnType<typeof vi.fn>;
    create:    ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    svc = {
      getSchema: vi.fn().mockReturnValue(of(RULE_SCHEMA)),
      get:       vi.fn().mockReturnValue(of(stored)),
      update:    vi.fn().mockReturnValue(of({
        ...stored, row_version: 8,
        warnings: [{ rule_id: 'r1', rule_name: 'Big deals', field: 'amount', message: 'Needs approval' }],
      })),
      create:    vi.fn(),
    };
    TestBed.configureTestingModule({
      imports: [TestFormComponent],
      providers: [
        { provide: EntityService, useValue: svc },
        {
          provide: Router,
          useValue: { navigate: vi.fn(), url: '/', parseUrl: () => ({ queryParamMap: { get: () => null } }) },
        },
      ],
    });
  });

  function editDeal() {
    const fixture = TestBed.createComponent(TestFormComponent);
    fixture.componentRef.setInput('name', 'deal');
    fixture.componentRef.setInput('id', 'deal-1');
    fixture.detectChanges();
    return fixture;
  }

  it('locks fields live when the condition starts to hold, most restrictive wins', () => {
    const fixture = editDeal();
    const c = fixture.componentInstance;
    expect(c.fieldLock('amount')).toBeNull();
    expect(c.form().get('amount')!.enabled).toBe(true);

    c.form().get('status')!.setValue('closed');
    fixture.detectChanges();

    expect(c.isDisabled('amount')).toBe(true);
    expect(c.lockReason('amount')).toBe('Closed deals');
    // `hidden` (closed_hide) beats `disabled` (closed_lock); no display name → name.
    expect(c.isHidden('notes')).toBe(true);
    expect(c.lockReason('notes')).toBe('closed_hide');
    expect(c.form().get('amount')!.disabled).toBe(true);
    expect(c.form().get('notes')!.disabled).toBe(true);
  });

  it('resets a locked control to its stored value and leaves it out of the save payload', () => {
    const fixture = editDeal();
    const c = fixture.componentInstance;
    c.form().get('amount')!.setValue(900);
    c.form().get('status')!.markAsDirty();
    c.form().get('status')!.setValue('closed');
    fixture.detectChanges();

    expect(c.form().get('amount')!.value).toBe(500);
    c.save();
    const sent = svc.update.mock.calls[0][2] as Record<string, unknown>;
    expect(sent).toEqual({ status: 'closed' });
  });

  it('unlocks again when the condition stops holding', () => {
    const fixture = editDeal();
    const c = fixture.componentInstance;
    c.form().get('status')!.setValue('closed');
    fixture.detectChanges();
    c.form().get('status')!.setValue('open');
    fixture.detectChanges();
    expect(c.fieldLock('amount')).toBeNull();
    expect(c.form().get('amount')!.enabled).toBe(true);
  });

  it('flags a required field that is locked and empty', () => {
    svc.get.mockReturnValue(of({ ...stored, data: { status: 'closed', amount: null, notes: null } }));
    const c = editDeal().componentInstance;
    expect(c.isRequiredLocked('amount')).toBe(true);
    expect(c.isRequiredLocked('status')).toBe(false);
  });

  it('shows field-attached rule messages live', () => {
    const fixture = editDeal();
    const c = fixture.componentInstance;
    expect(c.ruleMessages('amount')).toEqual([]);
    c.form().get('amount')!.setValue(5000);
    fixture.detectChanges();
    expect(c.ruleMessages('amount')).toEqual([
      { message: 'Needs approval', severity: 'warning', ruleName: 'Big deals' },
    ]);
  });

  it('keeps the write warnings of a successful save (D-791 rule 6)', () => {
    const fixture = editDeal();
    const c = fixture.componentInstance;
    c.form().get('amount')!.markAsDirty();
    c.form().get('amount')!.setValue(5000);
    c.save();
    expect(c.saveWarnings()).toEqual([
      { rule_id: 'r1', rule_name: 'Big deals', field: 'amount', message: 'Needs approval' },
    ]);
  });

  it('maps a field_locked refusal to its field', () => {
    svc.update.mockReturnValue(throwError(() => ({
      kind: 'validation', status: 422, code: 'field_locked',
      message: "'amount' is locked by the rule 'Closed deals' and cannot be changed",
    })));
    const fixture = editDeal();
    const c = fixture.componentInstance;
    c.form().get('amount')!.markAsDirty();
    c.form().get('amount')!.setValue(600);
    c.save();
    expect(c.error()).toContain('locked by the rule');
    expect(c.serverFieldErrors().get('amount')).toContain('locked by the rule');
  });
});
