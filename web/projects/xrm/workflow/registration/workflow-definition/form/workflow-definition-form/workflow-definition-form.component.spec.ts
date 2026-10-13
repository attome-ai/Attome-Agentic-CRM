import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import { Component, input } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { EMPTY, of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiService, ATTOME_CONFIG, LangService } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { EntityService, RecordTabPanelsComponent, XrmBaseFormComponent } from '@attome/xrm/core/entity';
import { WorkflowDefinitionFormComponent } from './workflow-definition-form.component';

// Regression coverage for the audit's finding 2b (AUDIT-2026-09-20 §2) — the
// second of the two templates that rendered `@if (error())` only, while
// `EngineFormBase.save()` routes a 409 to `conflict()` and leaves `error()` null.
// A stale `row_version` on a workflow-definition edit produced no UI at all.
//
// These assert the rendered DOM rather than the signal: the signal was always
// set correctly, so a signal-only test would have passed against the bug.
const SCHEMA: EntitySchema = {
  id: 'e1',
  name: 'Workflow',
  logical_name: 'workflow_definition',
  fields: [
    {
      id: 'f1', entity_id: 'e1', name: 'name', display_name: 'Name',
      field_type: 'text', options: null, sort_order: 0, is_required: false,
    },
    {
      id: 'f2', entity_id: 'e1', name: 'logicalname', display_name: 'Logical name',
      field_type: 'text', options: null, sort_order: 1, is_required: false,
    },
  ],
  relationships: [],
} as unknown as EntitySchema;

const RECORD = { id: 'wf-1', data: { name: 'Onboarding', logicalname: 'onboarding' }, row_version: 2 };

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
  stubRecordTabs();
}

describe('WorkflowDefinitionFormComponent — version-conflict surfacing', () => {
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
      imports: [WorkflowDefinitionFormComponent],
      providers: [
        { provide: EntityService, useValue: { ...inertEntityServiceMethods(), ...svc } },
        // `loadVersions()` hits the workflow engine's own admin API on init.
        // EMPTY, not a shape: the blanked side panels still run ngOnInit, and a
        // stub that emits makes each one parse a response it never asked for.
        { provide: ApiService, useValue: { get: vi.fn().mockReturnValue(EMPTY), post: vi.fn().mockReturnValue(EMPTY), put: vi.fn().mockReturnValue(EMPTY), patch: vi.fn().mockReturnValue(EMPTY), delete: vi.fn().mockReturnValue(EMPTY) } },
        { provide: Router, useValue: { navigate: vi.fn(), parseUrl: () => ({ queryParamMap: { get: () => null } }), url: '/' } },
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function renderDirty() {
    blankSidePanels();
    const fixture = TestBed.createComponent(WorkflowDefinitionFormComponent);
    fixture.componentRef.setInput('name', 'workflow_definition');
    fixture.componentRef.setInput('id', 'wf-1');
    fixture.detectChanges();
    const control = fixture.componentInstance.form().get('name');
    control!.setValue('Onboarding v2');
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

    expect(fixture.componentInstance.error()).toBeNull();
    expect(fixture.nativeElement.querySelector(ALERT)).not.toBeNull();
  });

  it('clears the alert when the operator uses the reload control', () => {
    const fixture = renderDirty();
    svc.update.mockReturnValue(throwError(() => ({ kind: 'version_conflict', message: 'stale row_version' })));
    fixture.componentInstance.save();
    fixture.detectChanges();
    expect(fixture.nativeElement.querySelector(ALERT)).not.toBeNull();

    svc.get.mockReturnValue(of({ ...RECORD, row_version: 3 }));
    fixture.nativeElement.querySelector(RELOAD).click();
    fixture.detectChanges();

    expect(svc.get).toHaveBeenCalledWith('workflow_definition', 'wf-1');
    expect(fixture.componentInstance.conflict()).toBe(false);
    expect(fixture.nativeElement.querySelector(ALERT)).toBeNull();
  });

  it('still shows the generic error banner for a non-conflict failure', () => {
    const fixture = renderDirty();
    svc.update.mockReturnValue(throwError(() => ({ kind: 'validation', message: 'Name is required.' })));

    fixture.componentInstance.save();
    fixture.detectChanges();

    expect(fixture.nativeElement.querySelector(ALERT)).toBeNull();
    expect(fixture.nativeElement.textContent).toContain('Name is required.');
  });
});
