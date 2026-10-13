import { TestBed, type ComponentFixture } from '@angular/core/testing';
import { LangService } from '@attome/base';
import type { EntitySchema, FieldSchema } from '@attome/xrm';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { formatSourceRef, sha256Hex } from '../csv/csv-chunks';
import { CsvImportService, type MigrationRunListItem } from '../csv/csv-import.service';
import { CsvImportComponent } from './csv-import.component';

function field(name: string, display: string, type: FieldSchema['field_type'] = 'text'): FieldSchema {
  return { id: name, entity_id: 'e', name, display_name: display, field_type: type, options: null, sort_order: 0, is_required: false };
}

const SCHEMA: EntitySchema = {
  id: 'e', name: 'contact', plural_name: 'contacts', relationships: [],
  fields: [field('full_name', 'Full name'), field('age', 'Age', 'number')],
};

const PROJECT = {
  id: 'proj-1', name: 'p', target_entity: 'contact', source_kind: 'csv', mapping_ref: 'map-1',
  status: 'draft', owner: 'u', created_by: 'u', created_at: '', updated_at: '', source_ref: null as string | null,
};

function csv(rows: number, extra = ''): Uint8Array {
  const lines = ['Full name,Age'];
  for (let i = 0; i < rows; i++) lines.push(`Person ${i},${i % 90}`);
  return new TextEncoder().encode(lines.join('\n') + extra);
}

function runItem(i: number, total: number, status = 'pending_review'): MigrationRunListItem {
  return {
    id: `run-${i}`, project_id: 'proj-1', staged_import_id: `si-${i}`, entity_logicalname: 'contact',
    operation: 'create', mode: 'stage', import_status: status, total, rejected: 0, rollback_status: 'none',
    created_by: 'u', created_at: `2026-09-23T10:00:${String(i).padStart(2, '0')}Z`,
  };
}

// Real parsing and chunking of files up to 50,001 rows: slower than a
// typical component spec when the whole suite runs in parallel.
describe('CsvImportComponent', { timeout: 30_000 }, () => {
  let svc: Record<string, ReturnType<typeof vi.fn>>;
  let staged: { body: { records: unknown[]; mode: string }; key?: string }[];

  beforeEach(() => {
    staged = [];
    let n = 0;
    svc = {
      schema: vi.fn(() => of(SCHEMA)),
      listMappings: vi.fn(() => of([])),
      listProjects: vi.fn(() => of([])),
      createMapping: vi.fn((body: { fields: unknown[] }) => of({ id: 'map-1', name: 'm', target_entity: 'contact', source_kind: 'csv', fields: body.fields })),
      createProject: vi.fn((body: { source_ref: string }) => of({ ...PROJECT, source_ref: body.source_ref })),
      completeProject: vi.fn(() => of(PROJECT)),
      stage: vi.fn(async (_entity: string, body: { records: unknown[]; mode: string }, key?: string) => {
        staged.push({ body, key });
        const passed = body.mode === 'dry_run' ? body.records.length - 1 : body.records.length;
        return { id: `si-${n++}`, status: 'pending_review', total: body.records.length, passed, failed: body.records.length - passed, rejected: 0 };
      }),
      linkRun: vi.fn(async () => ({ validation_report: [{ index: 1, status: 'failed', error: 'age is required' }] })),
      listRuns: vi.fn(async () => [] as MigrationRunListItem[]),
      approve: vi.fn(async () => ({})),
    };
    TestBed.configureTestingModule({
      imports: [CsvImportComponent],
      providers: [
        { provide: CsvImportService, useValue: svc },
        {
          provide: LangService,
          useValue: {
            intlLocale: () => 'en-US',
            translate: (key: string, params?: Record<string, unknown>) => (params ? `${key} ${JSON.stringify(params)}` : key),
          },
        },
      ],
    });
  });

  async function settle(fixture: ComponentFixture<CsvImportComponent>): Promise<void> {
    for (let i = 0; i < 40; i++) await new Promise(r => setTimeout(r, 0));
    fixture.detectChanges();
  }

  async function setup(bytes: Uint8Array) {
    const fixture = TestBed.createComponent(CsvImportComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = (id: string) => el.querySelector<HTMLElement>(`[data-testid="${id}"]`);
    const qa = (id: string) => Array.from(el.querySelectorAll<HTMLElement>(`[data-testid="${id}"]`));
    const entity = q('csv-entity') as HTMLInputElement;
    entity.value = 'contact';
    entity.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    q('csv-entity-load')!.click();
    await settle(fixture);
    await fixture.componentInstance.readFile('people.csv', bytes);
    await settle(fixture);
    return { fixture, el, q, qa };
  }

  it('previews the first 20 rows and maps headers to fields by display name', async () => {
    const { q, qa } = await setup(csv(30));
    expect(q('csv-summary')?.textContent).toContain('"rows":30');
    expect(q('csv-preview')!.querySelectorAll('tbody tr').length).toBe(20);
    const targets = qa('csv-target') as HTMLSelectElement[];
    expect(targets.map(s => s.value)).toEqual(['full_name', 'age']);
    expect(q('csv-ready')?.textContent).toContain('"count":30');
  });

  it('refuses a file over the 50,000-row cap with a clear message', async () => {
    const { q } = await setup(csv(50_001));
    expect(q('csv-too-many')?.getAttribute('role')).toBe('alert');
    expect(q('csv-too-many')?.textContent).toContain('csvImport.tooManyRows');
    expect(q('csv-preview')).toBeNull();
  });

  it('shows per-cell errors and blocks until the user chooses to skip those rows', async () => {
    const { fixture, q, qa } = await setup(csv(3, '\nBad,old\n'));
    expect(qa('csv-cell-error').map(e => e.textContent)).toEqual([
      expect.stringContaining('csvImport.cellError.number'),
    ]);
    expect(q('csv-blocker')?.textContent).toContain('csvImport.blocker.invalidRows');
    expect((q('csv-dry-run') as HTMLButtonElement).disabled).toBe(true);
    (q('csv-skip-invalid') as HTMLInputElement).click();
    fixture.detectChanges();
    expect((q('csv-dry-run') as HTMLButtonElement).disabled).toBe(false);
  });

  it('dry-runs the first chunk and shows its per-row errors', async () => {
    const { fixture, q, qa } = await setup(csv(700));
    q('csv-dry-run')!.click();
    await settle(fixture);
    expect(svc['createMapping']).toHaveBeenCalledWith({
      name: 'contact CSV',
      target_entity: 'contact',
      fields: [
        { source: 'Full name', target: 'full_name', lookup_resolution: 'by_id' },
        { source: 'Age', target: 'age', lookup_resolution: 'by_id' },
      ],
    });
    expect(staged).toHaveLength(1);
    expect(staged[0].body.mode).toBe('dry_run');
    expect(staged[0].body.records).toHaveLength(500);
    expect((staged[0].body as unknown as { mapping_ref: string }).mapping_ref).toBe('map-1');
    expect(q('csv-dry-run-result')?.textContent).toContain('csvImport.dryRunSummary');
    // Report index 1 of the first chunk is the file's third spreadsheet row.
    expect(qa('csv-dry-run-problem').map(e => e.textContent)).toEqual([
      expect.stringContaining('"row":3,"message":"age is required"'),
    ]);
  });

  it('stages every row in chunks of at most 500, then approves them all', async () => {
    const { fixture, q, qa } = await setup(csv(1200));
    q('csv-dry-run')!.click();
    await settle(fixture);
    staged = [];
    q('csv-stage')!.click();
    await settle(fixture);
    expect(staged.map(s => s.body.records.length)).toEqual([500, 500, 200]);
    expect(staged.every(s => s.body.mode === 'stage' && s.key?.startsWith('csv-stage:proj-1:'))).toBe(true);
    expect((q('csv-stage-progress') as HTMLProgressElement).value).toBe(3);

    svc['listRuns'].mockResolvedValue([runItem(0, 500), runItem(1, 500), runItem(2, 200)]);
    q('csv-approve')!.click();
    await settle(fixture);
    expect(svc['approve'].mock.calls.map(c => c[1]).sort()).toEqual(['si-0', 'si-1', 'si-2']);
    expect(svc['completeProject']).toHaveBeenCalledWith('proj-1');
    expect(q('csv-notice')?.textContent).toContain('csvImport.approvedNotice');
    expect(qa('csv-run-status').length).toBeGreaterThan(0);
  });

  it('resumes an earlier import of the same file, skipping chunks already staged', async () => {
    const bytes = csv(1200);
    const sourceRef = formatSourceRef({
      sha256: await sha256Hex(bytes), rows: 1200, encoding: 'utf-8', dateFormat: 'iso', decimal: '.',
    });
    svc['listProjects'].mockReturnValue(of([{ ...PROJECT, source_ref: sourceRef }]));
    svc['listMappings'].mockReturnValue(of([{
      id: 'map-1', name: 'm', target_entity: 'contact', source_kind: 'csv',
      fields: [
        { source: 'Full name', target: 'full_name', lookup_resolution: 'by_id' },
        { source: 'Age', target: 'age', lookup_resolution: 'by_id' },
      ],
    }]));
    // Chunks 0 and 1 were staged and linked before the failure.
    svc['listRuns'].mockResolvedValue([runItem(0, 500, 'approved'), runItem(1, 500)]);

    const fixture = TestBed.createComponent(CsvImportComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = (id: string) => el.querySelector<HTMLElement>(`[data-testid="${id}"]`);
    const entity = q('csv-entity') as HTMLInputElement;
    entity.value = 'contact';
    entity.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    q('csv-entity-load')!.click();
    await settle(fixture);
    const resume = q('csv-resume') as HTMLSelectElement;
    resume.value = 'proj-1';
    resume.dispatchEvent(new Event('change'));
    await fixture.componentInstance.readFile('people.csv', bytes);
    await settle(fixture);
    expect(q('csv-locked')).not.toBeNull();
    expect(q('csv-error')).toBeNull();

    q('csv-stage')!.click();
    await settle(fixture);
    expect(svc['createProject']).not.toHaveBeenCalled();
    expect(svc['createMapping']).not.toHaveBeenCalled();
    expect(staged.map(s => s.body.records.length)).toEqual([200]);
    expect(staged[0].key).toMatch(/^csv-stage:proj-1:2:/);
  });

  it('refuses to resume with a different file', async () => {
    const sourceRef = formatSourceRef({ sha256: 'f'.repeat(64), rows: 3, encoding: 'utf-8', dateFormat: 'iso', decimal: '.' });
    svc['listProjects'].mockReturnValue(of([{ ...PROJECT, source_ref: sourceRef }]));
    const fixture = TestBed.createComponent(CsvImportComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const q = (id: string) => el.querySelector<HTMLElement>(`[data-testid="${id}"]`);
    const entity = q('csv-entity') as HTMLInputElement;
    entity.value = 'contact';
    entity.dispatchEvent(new Event('input'));
    fixture.detectChanges();
    q('csv-entity-load')!.click();
    await settle(fixture);
    const resume = q('csv-resume') as HTMLSelectElement;
    resume.value = 'proj-1';
    resume.dispatchEvent(new Event('change'));
    await fixture.componentInstance.readFile('other.csv', csv(3));
    await settle(fixture);
    expect(q('csv-error')?.textContent).toContain('csvImport.error.wrongFile');
    q('csv-stage')!.click();
    await settle(fixture);
    expect(staged).toHaveLength(0);
  });
});
