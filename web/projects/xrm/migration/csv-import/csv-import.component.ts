import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import type { EntitySchema, FieldSchema } from '@attome/xrm';
import { firstValueFrom } from 'rxjs';
import { chunkBody, chunkRecords, formatSourceRef, parseSourceRef, sha256Hex, type ImportChunk } from '../csv/csv-chunks';
import { buildRecords, type BuiltRecords, type DateFormat, type DecimalSeparator, type RowError } from '../csv/csv-coerce';
import {
  approveRuns,
  ImportStopped,
  planResume,
  stageChunks,
  stagedRuns,
  type ImportPort,
} from '../csv/csv-import-runner';
import {
  CsvImportService,
  type DataMapping,
  type MigrationProject,
  type MigrationRunListItem,
  type StagedImportResponse,
  type ValidationReportItem,
} from '../csv/csv-import.service';
import {
  autoMatchColumns,
  columnsFromMapping,
  importableFields,
  mappingFieldsFromColumns,
  mappingProblems,
  sameMappingFields,
  unmatchedSources,
  type ColumnMapping,
  type LookupResolution,
} from '../csv/csv-mapping';
import {
  decodeCsvBytes,
  MAX_IMPORT_ROWS,
  parseCsv,
  type CsvDelimiter,
  type CsvEncoding,
  type ParsedCsv,
} from '../csv/csv-parser';

type Phase = 'setup' | 'dry-run' | 'staging' | 'staged' | 'approving' | 'done';

/** A server-reported problem with one file row. */
interface RowProblem {
  rowNumber: number;
  message: string;
}

/** The most server-reported row problems kept for display. */
const MAX_SHOWN_PROBLEMS = 200;
const PREVIEW_ROWS = 20;

/**
 * U11 / D-606 — CSV import, the migration wizard's file step. The file is
 * read and checked in the browser; the server sees only what already exists
 * for every import: a D-408 mapping (`data_mapping`), an M17
 * migration project, and staged imports of at most 500 records, each linked
 * to the project as a run and approved as a job. See `csv-import-runner.ts`
 * for why a resumed import never applies a row twice.
 */
@Component({
  selector: 'xrm-csv-import',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./csv-import.component.css'],
  templateUrl: './csv-import.component.html',
})
export class CsvImportComponent {
  private readonly svc = inject(CsvImportService);
  private readonly lang = inject(LangService);

  protected readonly maxRows = MAX_IMPORT_ROWS;
  protected readonly previewCount = PREVIEW_ROWS;

  // ── Target entity ──────────────────────────────────────────────────────────
  protected readonly entity = signal('');
  protected readonly schema = signal<EntitySchema | null>(null);
  protected readonly mappings = signal<DataMapping[]>([]);
  protected readonly projects = signal<MigrationProject[]>([]);
  protected readonly fields = computed(() => importableFields(this.schema()?.fields ?? []));

  // ── File ───────────────────────────────────────────────────────────────────
  protected readonly encodingChoice = signal<CsvEncoding | 'auto'>('auto');
  protected readonly delimiterChoice = signal<CsvDelimiter | 'auto'>('auto');
  protected readonly fileName = signal<string | null>(null);
  private fileBytes: Uint8Array | null = null;
  protected readonly fileSha = signal<string | null>(null);
  protected readonly encoding = signal<CsvEncoding | null>(null);
  protected readonly parsed = signal<ParsedCsv | null>(null);
  protected readonly previewRows = computed(() => this.parsed()?.rows.slice(0, PREVIEW_ROWS) ?? []);

  // ── Mapping and reading options ────────────────────────────────────────────
  protected readonly columns = signal<ColumnMapping[]>([]);
  protected readonly selectedMappingId = signal<string | null>(null);
  protected readonly mappingName = signal('');
  protected readonly dateFormat = signal<DateFormat>('iso');
  protected readonly decimal = signal<DecimalSeparator>('.');
  protected readonly skipInvalid = signal(false);

  protected readonly problems = computed(() => mappingProblems(this.columns(), this.fields()));
  protected readonly built = computed<BuiltRecords | null>(() => {
    const parsed = this.parsed();
    if (!parsed || parsed.tooManyRows || this.problems().length > 0) return null;
    return buildRecords(parsed, this.columns(), this.fields(), {
      dateFormat: this.dateFormat(),
      decimal: this.decimal(),
    });
  });
  protected readonly shownErrors = computed(() => this.built()?.errors.slice(0, 50) ?? []);

  // ── Import ─────────────────────────────────────────────────────────────────
  protected readonly project = signal<MigrationProject | null>(null);
  protected readonly resumeProjectId = signal<string | null>(null);
  protected readonly phase = signal<Phase>('setup');
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly dryRun = signal<{ staged: StagedImportResponse; problems: RowProblem[] } | null>(null);
  protected readonly chunkCount = signal(0);
  protected readonly chunksDone = signal(0);
  protected readonly stagedCounts = signal({ passed: 0, failed: 0, rejected: 0 });
  protected readonly stageProblems = signal<RowProblem[]>([]);
  protected readonly approveTotal = signal(0);
  protected readonly approved = signal(0);
  protected readonly runs = signal<MigrationRunListItem[]>([]);
  private stopRequested = false;
  private chunks: ImportChunk[] = [];

  /** A project exists: its mapping and reading options are fixed from here on. */
  protected readonly locked = computed(() => this.project() !== null);
  protected readonly stagePercent = computed(() =>
    this.chunkCount() ? Math.round((this.chunksDone() / this.chunkCount()) * 100) : 0,
  );
  protected readonly approvePercent = computed(() =>
    this.approveTotal() ? Math.round((this.approved() / this.approveTotal()) * 100) : 0,
  );
  protected readonly runStatusCounts = computed(() => {
    const counts: Record<string, number> = {};
    for (const run of stagedRuns(this.runs())) counts[run.import_status] = (counts[run.import_status] ?? 0) + 1;
    return Object.entries(counts).map(([status, count]) => ({ status, count }));
  });

  /** Why the import cannot start yet, as a catalog key, or null when it can. */
  protected readonly blocker = computed<string | null>(() => {
    const parsed = this.parsed();
    const built = this.built();
    if (!this.schema()) return 'csvImport.blocker.entity';
    if (!parsed) return 'csvImport.blocker.file';
    if (parsed.tooManyRows || parsed.unterminatedQuoteRow !== null) return 'csvImport.blocker.file';
    if (this.problems().length > 0 || !built) return 'csvImport.blocker.mapping';
    if (built.records.length === 0) return 'csvImport.blocker.noRows';
    if (built.invalidRows > 0 && !this.skipInvalid()) return 'csvImport.blocker.invalidRows';
    if (!this.project() && !this.mappingName().trim() && !this.reusableMapping()) return 'csvImport.blocker.mappingName';
    return null;
  });

  // ── Entity ─────────────────────────────────────────────────────────────────

  protected async loadEntity(): Promise<void> {
    const entity = this.entity().trim();
    if (!entity || this.locked()) return;
    this.error.set(null);
    this.busy.set(true);
    try {
      const [schema, mappings, projects] = await Promise.all([
        firstValueFrom(this.svc.schema(entity)),
        firstValueFrom(this.svc.listMappings(entity)),
        firstValueFrom(this.svc.listProjects(entity)),
      ]);
      this.schema.set(schema);
      this.mappings.set(mappings);
      this.projects.set(projects.filter(p => parseSourceRef(p.source_ref) !== null && p.mapping_ref));
      if (!this.mappingName()) this.mappingName.set(`${schema.name} CSV`);
      this.remap();
    } catch (e) {
      this.schema.set(null);
      this.error.set(this.message('csvImport.error.entity', e));
    } finally {
      this.busy.set(false);
    }
  }

  // ── File ───────────────────────────────────────────────────────────────────

  protected async onFile(event: Event): Promise<void> {
    const file = (event.target as HTMLInputElement).files?.[0];
    if (!file) return;
    await this.readFile(file.name, new Uint8Array(await file.arrayBuffer()));
  }

  /** Reads a file's bytes (separate from `onFile` so tests need no `File`). */
  async readFile(name: string, bytes: Uint8Array): Promise<void> {
    this.fileName.set(name);
    this.fileBytes = bytes;
    this.fileSha.set(await sha256Hex(bytes));
    this.reparse();
    this.checkResumeFile();
  }

  protected setEncoding(value: string): void {
    this.encodingChoice.set(value as CsvEncoding | 'auto');
    this.reparse();
  }

  protected setDelimiter(value: string): void {
    this.delimiterChoice.set(value as CsvDelimiter | 'auto');
    this.reparse();
  }

  private reparse(): void {
    if (!this.fileBytes) return;
    const forced = this.encodingChoice();
    const decoded = decodeCsvBytes(this.fileBytes, forced === 'auto' ? undefined : forced);
    const delimiter = this.delimiterChoice();
    this.encoding.set(decoded.encoding);
    this.parsed.set(parseCsv(decoded.text, delimiter === 'auto' ? {} : { delimiter }));
    this.remap();
  }

  /** Re-derives the column mapping from the chosen saved mapping, or by name. */
  private remap(): void {
    const parsed = this.parsed();
    if (!parsed) return;
    const mapping = this.selectedMapping();
    this.columns.set(
      mapping
        ? columnsFromMapping(parsed.headers, mapping.fields)
        : autoMatchColumns(parsed.headers, this.fields(), parsed.rows.slice(0, PREVIEW_ROWS)),
    );
  }

  // ── Mapping ────────────────────────────────────────────────────────────────

  protected selectedMapping(): DataMapping | null {
    return this.mappings().find(m => m.id === this.selectedMappingId()) ?? null;
  }

  /** Saved mapping sources this file has no column for. */
  protected readonly missingSources = computed(() => {
    const mapping = this.mappings().find(m => m.id === this.selectedMappingId());
    const parsed = this.parsed();
    return mapping && parsed ? unmatchedSources(parsed.headers, mapping.fields) : [];
  });

  /** The selected saved mapping, when the columns still say exactly what it says. */
  protected reusableMapping(): DataMapping | null {
    const mapping = this.selectedMapping();
    if (!mapping) return null;
    return sameMappingFields(mapping.fields, mappingFieldsFromColumns(this.columns(), this.fields())) ? mapping : null;
  }

  protected selectMapping(id: string): void {
    if (this.locked()) return;
    this.selectedMappingId.set(id || null);
    this.remap();
  }

  protected fieldFor(target: string | null): FieldSchema | null {
    return this.fields().find(f => f.name === target) ?? null;
  }

  protected setTarget(column: number, target: string): void {
    this.updateColumn(column, c => {
      const field = this.fieldFor(target || null);
      return {
        ...c,
        target: target || null,
        lookupResolution: field?.field_type === 'lookup' ? 'by_label' : 'by_id',
        lookupMatchField: null,
      };
    });
  }

  protected setResolution(column: number, value: string): void {
    this.updateColumn(column, c => ({ ...c, lookupResolution: value as LookupResolution }));
  }

  protected setMatchField(column: number, value: string): void {
    this.updateColumn(column, c => ({ ...c, lookupMatchField: value.trim() || null }));
  }

  private updateColumn(column: number, change: (c: ColumnMapping) => ColumnMapping): void {
    if (this.locked()) return;
    this.columns.update(cols => cols.map(c => (c.column === column ? change(c) : c)));
  }

  protected setDateFormat(value: string): void {
    if (!this.locked()) this.dateFormat.set(value as DateFormat);
  }

  protected setDecimal(value: string): void {
    if (!this.locked()) this.decimal.set(value as DecimalSeparator);
  }

  protected cellErrorText(e: RowError): string {
    return this.lang.translate(`csvImport.cellError.${e.code}`, {
      row: e.rowNumber,
      column: e.column ?? '',
      value: e.value,
    });
  }

  // ── Resume ─────────────────────────────────────────────────────────────────

  /**
   * Continue an earlier import: its project fixes the mapping and the
   * reading options, and the file must be the one it started with.
   */
  protected chooseResume(projectId: string): void {
    const project = this.projects().find(p => p.id === projectId) ?? null;
    const ref = parseSourceRef(project?.source_ref);
    if (!project || !ref) return;
    this.resumeProjectId.set(project.id);
    this.selectedMappingId.set(project.mapping_ref ?? null);
    this.encodingChoice.set(ref.encoding);
    this.dateFormat.set(ref.dateFormat);
    this.decimal.set(ref.decimal);
    this.skipInvalid.set(true);
    this.project.set(project);
    this.reparse();
    this.checkResumeFile();
  }

  private checkResumeFile(): void {
    const ref = parseSourceRef(this.project()?.source_ref);
    const sha = this.fileSha();
    if (!ref || !sha) return;
    this.error.set(sha === ref.sha256 ? null : this.lang.translate('csvImport.error.wrongFile'));
  }

  private wrongResumeFile(): boolean {
    const ref = parseSourceRef(this.project()?.source_ref);
    return !!ref && ref.sha256 !== this.fileSha();
  }

  // ── Dry run / stage / approve ──────────────────────────────────────────────

  private port(project: MigrationProject): ImportPort {
    const entity = project.target_entity;
    return {
      stage: (body, key) => this.svc.stage(entity, body, key),
      link: (id, key) => this.svc.linkRun(project.id, id, key),
      listRuns: () => this.svc.listRuns(project.id),
      approve: (id, key) => this.svc.approve(entity, id, key),
    };
  }

  /** The existing reusable mapping, or a new one saved under `mappingName`. */
  private async ensureProject(): Promise<MigrationProject> {
    const existing = this.project();
    if (existing) return existing;
    const schema = this.schema() as EntitySchema;
    let mapping = this.reusableMapping();
    if (!mapping) {
      mapping = await firstValueFrom(
        this.svc.createMapping({
          name: this.mappingName().trim(),
          target_entity: schema.name,
          fields: mappingFieldsFromColumns(this.columns(), this.fields()),
        }),
      );
      this.mappings.update(list => [mapping as DataMapping, ...list]);
      this.selectedMappingId.set(mapping.id);
    }
    const parsed = this.parsed() as ParsedCsv;
    const project = await firstValueFrom(
      this.svc.createProject({
        name: `${this.fileName() ?? 'import.csv'} — ${new Date().toISOString()}`,
        target_entity: schema.name,
        mapping_ref: mapping.id,
        source_ref: formatSourceRef({
          sha256: this.fileSha() as string,
          rows: parsed.rows.length,
          encoding: this.encoding() as CsvEncoding,
          dateFormat: this.dateFormat(),
          decimal: this.decimal(),
        }),
      }),
    );
    this.project.set(project);
    return project;
  }

  private buildChunks(): ImportChunk[] {
    this.chunks = chunkRecords(this.built()?.records ?? []);
    this.chunkCount.set(this.chunks.length);
    return this.chunks;
  }

  /** Dry-runs the first chunk and shows its per-row problems. Writes nothing. */
  protected async runDryRun(): Promise<void> {
    if (this.blocker() || this.busy() || this.wrongResumeFile()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      const project = await this.ensureProject();
      const first = this.buildChunks()[0];
      const staged = await this.svc.stage(project.target_entity, chunkBody(first, project.mapping_ref as string, 'dry_run'));
      // Linking the dry run (mode dry_run, never approvable) is what returns
      // its per-row report; it is not counted as a chunk.
      const run = await this.svc.linkRun(project.id, staged.id, `csv-link:${project.id}:${staged.id}`);
      this.dryRun.set({ staged, problems: this.rowProblems(first, run.validation_report) });
      this.phase.set('dry-run');
    } catch (e) {
      this.error.set(this.message('csvImport.error.dryRun', e));
    } finally {
      this.busy.set(false);
    }
  }

  /** Stages every chunk not yet staged for this project. */
  protected async stageAll(): Promise<void> {
    if (this.blocker() || this.busy() || this.wrongResumeFile()) return;
    this.busy.set(true);
    this.error.set(null);
    this.stopRequested = false;
    try {
      const project = await this.ensureProject();
      const chunks = this.buildChunks();
      const port = this.port(project);
      const plan = planResume(await port.listRuns(), chunks);
      if (plan.mismatch) {
        this.error.set(this.lang.translate('csvImport.error.resumeMismatch'));
        return;
      }
      this.chunksDone.set(plan.done);
      this.phase.set('staging');
      await stageChunks(port, chunks, {
        projectId: project.id,
        attempt: crypto.randomUUID(),
        mappingRef: project.mapping_ref as string,
        fromChunk: plan.done,
        shouldStop: () => this.stopRequested,
        onChunk: result => {
          this.chunksDone.update(n => n + 1);
          this.stagedCounts.update(c => ({
            passed: c.passed + result.passed,
            failed: c.failed + result.failed,
            rejected: c.rejected + result.rejected,
          }));
          if (result.problems.length) {
            this.stageProblems.update(list =>
              [...list, ...this.rowProblems(chunks[result.chunk], result.problems)].slice(0, MAX_SHOWN_PROBLEMS),
            );
          }
        },
      });
      this.runs.set(await port.listRuns());
      this.phase.set('staged');
    } catch (e) {
      this.phase.set(this.chunksDone() > 0 ? 'staging' : 'setup');
      this.error.set(
        e instanceof ImportStopped
          ? this.lang.translate('csvImport.stopped')
          : this.message('csvImport.error.stage', e),
      );
    } finally {
      this.busy.set(false);
    }
  }

  protected stop(): void {
    this.stopRequested = true;
  }

  /** Approves every staged chunk still waiting; each runs as a background job. */
  protected async approveAll(): Promise<void> {
    const project = this.project();
    if (!project || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      const port = this.port(project);
      const runs = await port.listRuns();
      const pending = stagedRuns(runs).filter(r => r.import_status === 'pending_review');
      this.approveTotal.set(pending.length);
      this.approved.set(0);
      this.phase.set('approving');
      await approveRuns(port, runs, () => this.approved.update(n => n + 1));
      this.runs.set(await port.listRuns());
      try {
        await firstValueFrom(this.svc.completeProject(project.id));
      } catch {
        // Marking the project completed is bookkeeping; the import itself is done.
      }
      this.phase.set('done');
      this.notice.set(this.lang.translate('csvImport.approvedNotice', { count: this.approved() }));
    } catch (e) {
      this.phase.set('staged');
      this.error.set(this.message('csvImport.error.approve', e));
    } finally {
      this.busy.set(false);
    }
  }

  /** Re-reads the runs: approved chunks apply in the background. */
  protected async refreshRuns(): Promise<void> {
    const project = this.project();
    if (!project) return;
    try {
      this.runs.set(await this.svc.listRuns(project.id));
    } catch (e) {
      this.error.set(this.message('csvImport.error.refresh', e));
    }
  }

  private rowProblems(chunk: ImportChunk, report: ValidationReportItem[]): RowProblem[] {
    const parsed = this.parsed();
    return report
      .filter(item => item.status !== 'passed' && item.status !== 'succeeded')
      .slice(0, MAX_SHOWN_PROBLEMS)
      .map(item => {
        const record = chunk.records[item.index];
        return {
          rowNumber: record && parsed ? parsed.rowNumbers[record.index] : item.index + 1,
          message: item.error ?? item.status,
        };
      });
  }

  private message(key: string, e: unknown): string {
    const err = e as ApiError | undefined;
    if (err?.status === 409) return this.lang.translate('csvImport.error.conflict', { message: err.message });
    if (err?.status === 403) return this.lang.translate('csvImport.error.forbidden');
    return this.lang.translate(key, { message: err?.message ?? String(e) });
  }
}
