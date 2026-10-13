import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import { Component, input } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { EMPTY, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, ATTOME_CONFIG, LangService } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { EntityService, FileUploadService, ImageUploadComponent, RecordTabPanelsComponent, RelatedGridComponent, TagsPanelComponent, XrmBaseFormComponent } from '@attome/xrm/core/entity';
import { UserSecurityPanelComponent } from '../user-security-panel/user-security-panel.component';
import { UserFormComponent } from './user-form.component';

// Regression coverage for the audit's finding 2b (AUDIT-2026-09-20 §2).
//
// `EngineFormBase.save()` routes a 409 to `conflict.set(true)` and deliberately
// does NOT set `error()` — the operator is meant to get a reload affordance,
// not a generic red banner. This template rendered `@if (error())` only, so a
// stale `row_version` on an admin editing a user produced *no UI at all*: the
// spinner stopped, the button returned to "Update", and the edit was silently
// discarded.
//
// These assert the rendered DOM, not the signal: a test that only checked
// `component.conflict()` would have passed against the broken template, since
// the signal was always being set correctly. The `data-testid` hooks match the
// generic dispatcher's own conflict banner and `e2e/tests/version-conflict.spec.ts`.
const SCHEMA: EntitySchema = {
  id: 'e1',
  name: 'User',
  logical_name: 'user_account',
  fields: [
    {
      id: 'f1', entity_id: 'e1', name: 'name', display_name: 'Name',
      field_type: 'text', options: null, sort_order: 0, is_required: false,
    },
  ],
  relationships: [],
} as unknown as EntitySchema;

const RECORD = { id: 'rec-1', data: { name: 'Ada' }, row_version: 3 };

const ALERT = '[data-testid="version-conflict-alert"]';
const RELOAD = '[data-testid="version-conflict-reload"]';

// Every other `EntityService` method the blanked side panels reach on init
// (NotesPanel calls `list`, related grids call `listRelated`, ...). Inert
// rather than shaped: these tests are about the conflict banner, and a stub
// that emits makes each panel parse a response nobody asked it for.
const INERT_ENTITY_SERVICE_METHODS = [
  'bulkStatus', 'bulkUpdate', 'delete', 'exportRecords', 'exportStatus', 'hardDelete',
  'invalidateSchema', 'linkRelated', 'list', 'listRelated', 'listTransitions',
  'lookupSearch', 'restore', 'transition', 'unlinkRelated',
] as const;

function inertEntityServiceMethods(): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const m of INERT_ENTITY_SERVICE_METHODS) out[m] = vi.fn().mockReturnValue(EMPTY);
  return out;
}

// The form's side panels (documents, notes, related grids, ...) fetch on init
// and are not what these tests are about; blanking their templates keeps the
// component under test rendering its OWN real template -- which is where the
// conflict banner lives and is therefore the only thing worth asserting here.
// D-773: the record tabs render inside <xrm-base-form>; each panel has its own
// spec and fetches on init, so a stub with the same selector and inputs
// stands in for them here.
@Component({ selector: 'xrm-record-tab-panels', standalone: true, template: '' })
class RecordTabPanelsStubComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input<string | null>(null);
  readonly tabs       = input.required<XrmFormTabDef[]>();
  readonly activeTab  = input.required<string>();
  readonly idPrefix   = input('entity');
}

function stubRecordTabs(): void {
  TestBed.overrideComponent(XrmBaseFormComponent, {
    remove: { imports: [RecordTabPanelsComponent] },
    add: { imports: [RecordTabPanelsStubComponent] },
  });
}

function blankSidePanels(): void {
  for (const cmp of [ImageUploadComponent, RelatedGridComponent, TagsPanelComponent, UserSecurityPanelComponent]) {
    TestBed.overrideComponent(cmp, { set: { template: '' } });
  }
  stubRecordTabs();
}

const files = { getDownloadUrl: vi.fn().mockReturnValue(of({ download_url: 'https://files.test/ada.png' })) };

describe('UserFormComponent — version-conflict surfacing', () => {
  let svc: {
    getSchema: ReturnType<typeof vi.fn>;
    get: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
    create: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    svc = {
      getSchema: vi.fn().mockReturnValue(of(SCHEMA)),
      get: vi.fn().mockReturnValue(of(RECORD)),
      update: vi.fn(),
      create: vi.fn(),
    };
    TestBed.configureTestingModule({
      imports: [UserFormComponent],
      providers: [
        { provide: EntityService, useValue: { ...inertEntityServiceMethods(), ...svc } },
        { provide: FileUploadService, useValue: files },
        // EMPTY, not a shape: the blanked side panels still run ngOnInit, and a
        // stub that emits makes each one parse a response it never asked for.
        { provide: ApiService, useValue: { get: vi.fn().mockReturnValue(EMPTY), getAllPages: vi.fn().mockReturnValue(EMPTY), post: vi.fn().mockReturnValue(EMPTY), put: vi.fn().mockReturnValue(EMPTY), patch: vi.fn().mockReturnValue(EMPTY), delete: vi.fn().mockReturnValue(EMPTY) } },
        { provide: Router, useValue: { navigate: vi.fn(), parseUrl: () => ({ queryParamMap: { get: () => null } }), url: '/' } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        // Echoes the key, so assertions target structure rather than a catalog.
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  /** An edit-mode form with a dirty control, i.e. one that `canSave()` allows. */
  function renderDirty() {
    blankSidePanels();
    const fixture = TestBed.createComponent(UserFormComponent);
    fixture.componentRef.setInput('name', 'user_account');
    fixture.componentRef.setInput('id', 'rec-1');
    fixture.detectChanges();
    const control = fixture.componentInstance.form().get('name');
    control!.setValue('Ada Lovelace');
    control!.markAsDirty();
    fixture.componentInstance.form().updateValueAndValidity();
    fixture.detectChanges();
    return fixture;
  }

  it('renders no conflict alert before a save is attempted', () => {
    const fixture = renderDirty();
    expect(fixture.nativeElement.querySelector(ALERT)).toBeNull();
  });

  it('renders the conflict alert and a reload control when a save 409s', () => {
    const fixture = renderDirty();
    svc.update.mockReturnValue(throwError(() => ({ kind: 'version_conflict', message: 'stale row_version' })));

    fixture.componentInstance.save();
    fixture.detectChanges();

    expect(fixture.componentInstance.conflict()).toBe(true);
    const alert = fixture.nativeElement.querySelector(ALERT);
    expect(alert, 'a version conflict must be visible to the operator').not.toBeNull();
    expect(alert.getAttribute('role')).toBe('alert');
    expect(fixture.nativeElement.querySelector(RELOAD), 'the operator needs a recovery path').not.toBeNull();
  });

  it('does not silently swallow the 409 into the generic error banner path', () => {
    const fixture = renderDirty();
    svc.update.mockReturnValue(throwError(() => ({ kind: 'version_conflict', message: 'stale row_version' })));

    fixture.componentInstance.save();
    fixture.detectChanges();

    // The exact defect: `error()` stays null on a version conflict, so a
    // template with only an `@if (error())` branch renders nothing at all.
    expect(fixture.componentInstance.error()).toBeNull();
    expect(fixture.nativeElement.querySelector(ALERT)).not.toBeNull();
  });

  it('clears the alert when the operator uses the reload control', () => {
    const fixture = renderDirty();
    svc.update.mockReturnValue(throwError(() => ({ kind: 'version_conflict', message: 'stale row_version' })));
    fixture.componentInstance.save();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector(ALERT)).not.toBeNull();

    svc.get.mockReturnValue(of({ ...RECORD, row_version: 4 }));
    fixture.nativeElement.querySelector(RELOAD).click();
    fixture.detectChanges();

    expect(svc.get).toHaveBeenCalledWith('user_account', 'rec-1');
    expect(fixture.componentInstance.conflict()).toBe(false);
    expect(fixture.nativeElement.querySelector(ALERT)).toBeNull();
  });

  it('still shows the generic error banner for a non-conflict failure', () => {
    const fixture = renderDirty();
    svc.update.mockReturnValue(throwError(() => ({ kind: 'validation', message: 'Email is required.' })));

    fixture.componentInstance.save();
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector(ALERT)).toBeNull();
    expect(fixture.nativeElement.textContent).toContain('Email is required.');
  });
});

// The live `user_account` schema (GET /api/v1/schema, 2026-09-27),
// so these exercise the controls a real deployment renders.
function field(name: string, field_type: string, options: unknown = null) {
  return {
    id: `f-${name}`, entity_id: 'e1', name, display_name: name,
    field_type, options, sort_order: 0, is_required: false,
  };
}

const LIVE_SCHEMA = {
  id: 'e1', name: 'User', logical_name: 'user_account', relationships: [],
  fields: [
    field('auth_type', 'number'), field('currency', 'number'), field('email', 'text'),
    field('is_active', 'bool'), field('language', 'number'), field('last_login', 'date'),
    field('locale', 'text'), field('max_page_size', 'number'), field('phone', 'text'),
    field('status', 'choice', { choices: ['online', 'away', 'busy', 'offline'], multi: false }),
    field('theme', 'text'), field('timezone', 'text'), field('user_name', 'text'),
  ],
} as unknown as EntitySchema;

describe('UserFormComponent — content', () => {
  let svc: { getSchema: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn>; update: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    svc = {
      getSchema: vi.fn().mockReturnValue(of(LIVE_SCHEMA)),
      get: vi.fn().mockReturnValue(of({
        id: 'rec-1', row_version: 1,
        data: { email: 'ada@example.com', user_name: 'ada', is_active: true, timezone: null, last_login: '2026-09-01T08:00:00Z' },
      })),
      update: vi.fn().mockReturnValue(EMPTY),
      create: vi.fn().mockReturnValue(EMPTY),
    };
    TestBed.configureTestingModule({
      imports: [UserFormComponent],
      providers: [
        { provide: EntityService, useValue: { ...inertEntityServiceMethods(), ...svc } },
        { provide: FileUploadService, useValue: files },
        { provide: ApiService, useValue: { get: vi.fn().mockReturnValue(EMPTY), getAllPages: vi.fn().mockReturnValue(EMPTY), post: vi.fn().mockReturnValue(EMPTY), put: vi.fn().mockReturnValue(EMPTY), patch: vi.fn().mockReturnValue(EMPTY), delete: vi.fn().mockReturnValue(EMPTY) } },
        { provide: Router, useValue: { navigate: vi.fn(), parseUrl: () => ({ queryParamMap: { get: () => null } }), url: '/' } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function render(id: string | null) {
    blankSidePanels();
    const fixture = TestBed.createComponent(UserFormComponent);
    fixture.componentRef.setInput('name', 'user_account');
    if (id) fixture.componentRef.setInput('id', id);
    fixture.detectChanges();
    return fixture;
  }

  const el = (f: { nativeElement: HTMLElement }, sel: string) => f.nativeElement.querySelector<HTMLElement>(sel);

  it('renders no switch for is_active: the generic save drops that column', () => {
    const f = render('rec-1');
    expect(el(f, 'input[formcontrolname="is_active"]')).toBeNull();
  });

  it('renders no controls for preferences nothing applies', () => {
    const f = render('rec-1');
    for (const name of ['theme', 'language', 'currency', 'max_page_size', 'locale']) {
      expect(el(f, `[formcontrolname="${name}"]`), name).toBeNull();
    }
    expect(el(f, '#timezone')).not.toBeNull();
  });

  it('flags an invalid email on the field itself', () => {
    const f = render('rec-1');
    const ctrl = f.componentInstance.form().get('email')!;
    ctrl.setValue('not-an-email');
    ctrl.markAsTouched();
    f.detectChanges();
    expect(el(f, '[data-testid="email-error"]')).not.toBeNull();
    const input = el(f, '#email')!;
    expect(input.getAttribute('aria-invalid')).toBe('true');
    // The input's description is the error text, not just any element.
    const described = el(f, `#${input.getAttribute('aria-describedby')}`)!;
    expect(described.getAttribute('data-testid')).toBe('email-error');
  });

  it('rejects a timezone Intl does not know, and accepts blank', () => {
    const f = render('rec-1');
    const ctrl = f.componentInstance.form().get('timezone')!;
    ctrl.setValue('Mars/Olympus');
    ctrl.markAsTouched();
    f.detectChanges();
    expect(el(f, '[data-testid="timezone-error"]')).not.toBeNull();
    ctrl.setValue('Asia/Dubai');
    f.detectChanges();
    expect(el(f, '[data-testid="timezone-error"]')).toBeNull();
    ctrl.setValue('');
    expect(ctrl.valid).toBe(true);
  });

  it('explains a refused save instead of silently doing nothing', () => {
    const f = render('rec-1');
    const ctrl = f.componentInstance.form().get('email')!;
    ctrl.setValue('broken');
    ctrl.markAsDirty();
    f.componentInstance.form().updateValueAndValidity();
    f.detectChanges();
    f.componentInstance.save();
    f.detectChanges();
    expect(svc.update).not.toHaveBeenCalled();
    expect(el(f, '[data-testid="entity-validation-alert"]')!.getAttribute('role')).toBe('alert');
  });

  it('tells the admin how a new user will sign in', () => {
    const f = render(null);
    expect(el(f, '[data-testid="create-signin-note"]')!.textContent).toContain('userForm.createSignInNote');
    expect(el(f, 'xrm-user-security-panel')).toBeNull();
  });

  it('mounts the security panel for an existing user, with last sign-in', () => {
    const f = render('rec-1');
    expect(el(f, 'xrm-user-security-panel')).not.toBeNull();
    expect(f.componentInstance.lastLogin()).toBe('2026-09-01T08:00:00Z');
  });

  it('translates tab labels', () => {
    const f = render('rec-1');
    const labels = Array.from(f.nativeElement.querySelectorAll('[role="tab"]')).map(t => (t as HTMLElement).textContent!.trim());
    // Details, Access and Settings are the form's own; the platform record
    // tabs follow (D-773), without Tags, which sit in Details.
    expect(labels.slice(0, 3)).toEqual(['userForm.tabs.details', 'userForm.tabs.access', 'userForm.tabs.settings']);
    expect(labels).toContain('xrmForm.tabs.notes');
    expect(labels).toContain('xrmForm.tabs.documents');
    expect(labels).not.toContain('xrmForm.tabs.tags');
  });

  it('heads the page with who is being edited, and no status badge', () => {
    const f = render('rec-1');
    expect(el(f, '[data-testid="header-title"]')!.textContent!.trim()).toBe('ada');
    expect(el(f, '[data-testid="header-status"]')).toBeNull();
  });

  it('shows no avatar icon and no email line in the header', () => {
    const f = render('rec-1');
    expect(el(f, '[data-testid="header-avatar"]')).toBeNull();
    expect(el(f, '[data-testid="header-initials"]')).toBeNull();
    expect(el(f, '.xf-meta-email')).toBeNull();
    expect(el(f, '.xf-identity')!.textContent).not.toContain('ada@example.com');
  });

  it('follows the security panel when the account is deactivated', () => {
    const f = render('rec-1');
    f.componentInstance.accountActive.set(false);
    f.detectChanges();
    expect(el(f, '[data-testid="deactivated-notice"]')).not.toBeNull();
  });

  it('brings Details forward when Save is refused from another tab', () => {
    const f = render('rec-1');
    f.componentInstance.selectTab('access');
    const ctrl = f.componentInstance.form().get('email')!;
    ctrl.setValue('broken');
    ctrl.markAsDirty();
    f.componentInstance.form().updateValueAndValidity();
    f.detectChanges();
    f.componentInstance.save();
    f.detectChanges();
    expect(f.componentInstance.activeTab()).toBe('details');
    expect(svc.update).not.toHaveBeenCalled();
  });

  it('locks Details for a deactivated account instead of letting the save 404', () => {
    const f = render('rec-1');
    f.componentInstance.accountActive.set(false);
    const ctrl = f.componentInstance.form().get('phone')!;
    ctrl.setValue('+971 50 000 0000');
    ctrl.markAsDirty();
    f.componentInstance.form().updateValueAndValidity();
    f.detectChanges();
    expect(el(f, '[data-testid="deactivated-notice"]')).not.toBeNull();
    expect((el(f, '#user-panel-details fieldset') as HTMLFieldSetElement).disabled).toBe(true);
    expect((el(f, 'button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
    f.componentInstance.save();
    expect(svc.update).not.toHaveBeenCalled();
  });

  it('marks the Details tab while it has unsaved changes', () => {
    const f = render('rec-1');
    expect(el(f, '[data-testid="unsaved-dot"]')).toBeNull();
    const ctrl = f.componentInstance.form().get('phone')!;
    ctrl.setValue('+971 50 000 0000');
    ctrl.markAsDirty();
    f.componentInstance.form().updateValueAndValidity();
    f.detectChanges();
    const tab = el(f, '#user-tab-details')!;
    expect(tab.querySelector('[data-testid="unsaved-dot"]')).not.toBeNull();
    expect(tab.textContent).toContain('xrmForm.unsavedChanges');
  });
});
