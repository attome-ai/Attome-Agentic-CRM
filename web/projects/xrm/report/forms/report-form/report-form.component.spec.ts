import { TestBed } from '@angular/core/testing';
import { Component, input, signal } from '@angular/core';
import { Router } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { provideHttpClientTesting } from '@angular/common/http/testing';
import { Observable, Subject, of, throwError } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ATTOME_CONFIG, LangService } from '@attome/base';
import { EntityService, RecordTabPanelsComponent, XrmBaseFormComponent } from '@attome/xrm/core/entity';
import type { XrmFormTabDef } from '@attome/xrm/core/entity';
import type { EntitySchema } from '@attome/xrm';
import { ReportFormComponent } from './report-form.component';
import { ReportRunService, ReportRunStatus } from '../../services/report-run.service';

// The record tabs (D-773: rendered by <xrm-base-form>) have their own specs
// and each fetches on init; a stub with the same selector and inputs keeps
// this spec on the Run behaviour.
@Component({ selector: 'xrm-record-tab-panels', standalone: true, template: '' })
class RecordTabPanelsStubComponent {
  readonly entityName = input.required<string>();
  readonly recordId   = input<string | null>(null);
  readonly tabs       = input.required<XrmFormTabDef[]>();
  readonly activeTab  = input.required<string>();
  readonly idPrefix   = input('entity');
}

const SCHEMA = {
  id: 'e1', name: 'Report', logical_name: 'attome_report',
  fields: [
    { id: 'f1', entity_id: 'e1', name: 'name', display_name: 'Name', field_type: 'text', options: null, sort_order: 0, is_required: false },
    { id: 'f2', entity_id: 'e1', name: 'format', display_name: 'Format', field_type: 'text', options: null, sort_order: 1, is_required: false },
  ],
} as unknown as EntitySchema;

function run(state: string, extra: Partial<ReportRunStatus> = {}): ReportRunStatus {
  return { id: 'run-1', report_ref: 'rep-1', format: 'xlsx', status: state, requested_at: '2026-09-23T10:00:00Z', ...extra };
}

describe('ReportFormComponent — Run (U16)', () => {
  let runAndWait: ReturnType<typeof vi.fn>;
  let openSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    runAndWait = vi.fn();
    openSpy = vi.spyOn(window, 'open').mockImplementation(() => null);
    TestBed.configureTestingModule({
      imports: [ReportFormComponent],
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        {
          provide: EntityService,
          useValue: {
            getSchema: () => of(SCHEMA),
            get: () => of({ id: 'rep-1', row_version: 1, data: { name: 'Pipeline', format: 'xlsx' } }),
          },
        },
        { provide: ReportRunService, useValue: { runAndWait } },
        {
          provide: Router,
          useValue: { navigate: vi.fn(), url: '/', parseUrl: () => ({ queryParamMap: { get: () => null } }) },
        },
        {
          provide: LangService,
          useValue: {
            translate: (key: string, params?: Record<string, unknown>) =>
              params ? `${key}:${JSON.stringify(params)}` : key,
            current: signal('en'),
          },
        },
      ],
    });
    TestBed.overrideComponent(XrmBaseFormComponent, {
      remove: { imports: [RecordTabPanelsComponent] },
      add: { imports: [RecordTabPanelsStubComponent] },
    });
  });

  afterEach(() => openSpy.mockRestore());

  function create(id: string | null = 'rep-1') {
    const fixture = TestBed.createComponent(ReportFormComponent);
    fixture.componentRef.setInput('name', 'attome_report');
    fixture.componentRef.setInput('id', id);
    fixture.detectChanges();
    return { fixture, cmp: fixture.componentInstance, el: fixture.nativeElement as HTMLElement };
  }

  function runButton(el: HTMLElement): HTMLButtonElement | undefined {
    return Array.from(el.querySelectorAll<HTMLButtonElement>('.xf-actions button'))
      .find(b => b.textContent?.includes('reportRun.'));
  }

  it('offers Run only on a saved record', () => {
    expect(runButton(create(null).el)).toBeUndefined();
    expect(runButton(create().el)).toBeDefined();
  });

  it('runs, shows the running state, then opens and links the download URL', () => {
    const pending = new Subject<ReportRunStatus>();
    runAndWait.mockReturnValue(pending);
    const { fixture, cmp, el } = create();

    runButton(el)!.click();
    fixture.detectChanges();
    expect(runAndWait).toHaveBeenCalledWith('rep-1');
    expect(cmp.runState()).toBe('running');
    expect(runButton(el)!.disabled).toBe(true);
    expect(el.querySelector('.report-run-banner[role="status"]')).not.toBeNull();

    pending.next(run('completed', { row_count: 12, download_url: 'http://storage/r.xlsx' }));
    pending.complete();
    fixture.detectChanges();

    expect(cmp.runState()).toBe('completed');
    expect(openSpy).toHaveBeenCalledWith('http://storage/r.xlsx', '_blank', 'noopener');
    const link = el.querySelector<HTMLAnchorElement>('.report-run-banner--ok a');
    expect(link?.getAttribute('href')).toBe('http://storage/r.xlsx');
  });

  it('shows a failed run with its error as an alert', () => {
    runAndWait.mockReturnValue(of(run('failed', { error: 'query timed out' })));
    const { fixture, cmp, el } = create();

    cmp.runReport();
    fixture.detectChanges();

    expect(cmp.runState()).toBe('failed');
    expect(el.querySelector('[role="alert"]')!.textContent).toContain('query timed out');
    expect(openSpy).not.toHaveBeenCalled();
  });

  it('shows a request failure (for example 403) as a failed run', () => {
    runAndWait.mockReturnValue(throwError(() => ({ message: 'Forbidden' })) as Observable<ReportRunStatus>);
    const { cmp } = create();

    cmp.runReport();

    expect(cmp.runState()).toBe('failed');
    expect(cmp.runError()).toBe('Forbidden');
  });

  it('reports a run that outlived the poll budget as still running, not failed', () => {
    runAndWait.mockReturnValue(of(run('running')));
    const { cmp } = create();

    cmp.runReport();

    expect(cmp.runState()).toBe('timeout');
    expect(openSpy).not.toHaveBeenCalled();
  });

  it('does not run while the form holds unsaved edits', () => {
    const { fixture, cmp, el } = create();
    const control = cmp.form().get('name')!;
    control.markAsDirty();
    control.setValue('Edited');
    fixture.detectChanges();

    cmp.runReport();

    expect(runAndWait).not.toHaveBeenCalled();
    expect(runButton(el)!.disabled).toBe(true);
  });
});
