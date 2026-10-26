import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntitySchema, FieldSchema } from '@attome/xrm';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { CsvImportService } from '../csv/csv-import.service';
import { ImportJobService, type ImportJob } from '../csv/import-job.service';
import { CsvImportComponent } from './csv-import.component';

function field(name: string, display: string, type: FieldSchema['field_type'] = 'text'): FieldSchema {
  return { id: name, entity_id: 'e', name, display_name: display, field_type: type, options: null, sort_order: 0, is_required: false };
}

const SCHEMA: EntitySchema = {
  id: 'e', name: 'contact', plural_name: 'contacts', relationships: [],
  fields: [field('full_name', 'Full name'), field('age', 'Age', 'number')],
};

function job(status: string, counts: Record<string, unknown> = {}): ImportJob {
  return {
    id: 'job-1', entity_logicalname: 'contact', file_name: 'people.csv', status,
    counts, mapping: {}, match_mode: 'upsert', match_columns: [], all_or_nothing: false,
    triggers_on: false, created_by: 'u', created_at: '2026-10-26T08:00:00Z', finished_at: null, row_version: 1,
  } as unknown as ImportJob;
}

const CSV = new TextEncoder().encode('Full name,Age\nسارة,30\nOmar,41\nLina,x');

describe('CsvImportComponent', () => {
  let jobs: Record<string, ReturnType<typeof vi.fn>>;
  let fixture: ComponentFixture<CsvImportComponent>;
  let component: CsvImportComponent;

  beforeEach(async () => {
    jobs = {
      list: vi.fn(() => of([])),
      upload: vi.fn(() => of({ job_id: 'job-1', existing: false })),
      get: vi.fn(() => of(job('validated', { create: 2, update: 0, skip: 0, invalid: 1, duplicates: 0 }))),
      preview: vi.fn(() => of({
        job_id: 'job-1',
        masked: [],
        rows: [
          { row_no: 1, status: 'valid', action: 'create', mapped: { full_name: 'سارة', age: 30 }, error: null },
          { row_no: 3, status: 'invalid', action: null, mapped: { full_name: 'Lina' },
            error: { errors: [{ field: 'age', code: 'invalid_number', message_key: 'import.error.invalid_number' }] } },
        ],
      })),
      apply: vi.fn(() => of({ job_id: 'job-1', status: 'validated', approval_request_id: null })),
      undo: vi.fn(() => of({ job_id: 'job-1', status: 'applied', approval_request_id: null })),
      update: vi.fn(() => of(job('staged'))),
      dryRun: vi.fn(() => of({ job_id: 'job-1', status: 'staged', approval_request_id: null })),
      cancel: vi.fn(() => of({ job_id: 'job-1', status: 'cancelled', approval_request_id: null })),
      proposeMapping: vi.fn(() => of(null)),
      errorFileUrl: vi.fn(() => '/api/v1/contact/imports/job-1/errors'),
    };
    await TestBed.configureTestingModule({
      imports: [CsvImportComponent],
      providers: [
        { provide: CsvImportService, useValue: { schema: vi.fn(() => of(SCHEMA)) } },
        { provide: ImportJobService, useValue: jobs },
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US',
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
          },
        },
      ],
    }).compileComponents();
    fixture = TestBed.createComponent(CsvImportComponent);
    component = fixture.componentInstance;
    component.entity.set('contact');
    await component.loadEntity();
    await component.readFile('people.csv', CSV);
    fixture.detectChanges();
  });

  it('matches columns by name from the instant preview', () => {
    expect(component.columns().map(c => c.target)).toEqual(['full_name', 'age']);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="import-client-preview"]')?.textContent).toContain('سارة');
  });

  it('shows dry run counts before apply', async () => {
    await component.upload();
    fixture.detectChanges();
    expect(jobs['upload']).toHaveBeenCalledOnce();
    const [, , name, options, dryRun] = jobs['upload'].mock.calls[0];
    expect(name).toBe('people.csv');
    expect(dryRun).toBe(true);
    expect(options.mapping.columns).toEqual([
      { source: 'Full name', target: 'full_name' },
      { source: 'Age', target: 'age' },
    ]);
    expect(component.phase()).toBe('checked');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="import-counts"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="import-apply"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="import-error-file"]')?.getAttribute('href'))
      .toBe('/api/v1/contact/imports/job-1/errors');
    expect(jobs['apply']).not.toHaveBeenCalled();
  });

  it('undo button calls undo route', async () => {
    await component.upload();
    jobs['get'].mockReturnValue(of(job('applied', { applied: 2, apply_failed: 0, create: 2 })));
    await component.apply();
    fixture.detectChanges();
    expect(component.phase()).toBe('done');
    jobs['get'].mockReturnValue(of(job('undone', { undo: { reverted: 2, skipped: 0 } })));
    const undo = (fixture.nativeElement as HTMLElement).querySelector<HTMLButtonElement>('[data-testid="import-undo"]');
    expect(undo).not.toBeNull();
    undo?.click();
    await fixture.whenStable();
    await vi.waitFor(() => expect(jobs['undo']).toHaveBeenCalledWith('contact', 'job-1'));
    await vi.waitFor(() => expect(component.phase()).toBe('undone'));
  });

  it('waits for approval instead of applying when the policy asks', async () => {
    await component.upload();
    jobs['apply'].mockReturnValue(of({ job_id: 'job-1', status: 'awaiting_approval', approval_request_id: 'req-1' }));
    await component.apply();
    expect(component.phase()).toBe('awaiting');
  });
});
