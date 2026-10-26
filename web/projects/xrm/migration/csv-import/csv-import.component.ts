import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { firstValueFrom } from 'rxjs';
import { CsvImportService } from '../csv/csv-import.service';
import {
  countsOf,
  ImportJobService,
  type ImportJob,
  type ImportOptionsBody,
  type ImportPreviewRow,
} from '../csv/import-job.service';
import { autoMatchColumns, importableFields } from '../csv/csv-mapping';
import { decodeCsvBytes, parseCsv, type CsvEncoding, type ParsedCsv } from '../csv/csv-parser';

/** Where the wizard is. */
type Phase = 'setup' | 'working' | 'checked' | 'awaiting' | 'done' | 'undone' | 'failed';

/** One file column and the field it fills. */
interface MappedColumn {
  source: string;
  target: string | null;
  /** The mapping agent's confidence, 0 to 1, when it proposed this column. */
  confidence: number | null;
}

type MatchMode = 'create' | 'update' | 'upsert';

/** Rows of the instant preview read in the browser. */
const CLIENT_PREVIEW_ROWS = 50;
/** How often, and how many times, a running job is re-read. */
const POLL_MS = 1500;
const POLL_TRIES = 400;

/**
 * A23-T13 — the import wizard on the server's import job. The browser reads
 * the first 50 rows only, to show the file at once and match columns by
 * name; the file itself goes to the server, which stages it, checks it (a
 * dry run with counts and per-row errors), applies it in the background and
 * can undo it. The mapping agent can propose each column's field with a
 * confidence badge; every proposal stays editable.
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
  private readonly schemas = inject(CsvImportService);
  private readonly jobs = inject(ImportJobService);
  private readonly lang = inject(LangService);

  // ── Target entity ──────────────────────────────────────────────────────────
  readonly entity = signal('');
  protected readonly schema = signal<EntitySchema | null>(null);
  protected readonly fields = computed(() => importableFields(this.schema()?.fields ?? []));
  protected readonly recent = signal<ImportJob[]>([]);

  // ── File ───────────────────────────────────────────────────────────────────
  protected readonly fileName = signal<string | null>(null);
  private readonly file = signal<Blob | null>(null);
  protected readonly encoding = signal<CsvEncoding | null>(null);
  protected readonly parsed = signal<ParsedCsv | null>(null);
  protected readonly clientRows = computed(() => this.parsed()?.rows.slice(0, 10) ?? []);
  protected readonly isSpreadsheet = computed(() => (this.fileName() ?? '').toLowerCase().endsWith('.xlsx'));

  // ── Mapping and options ────────────────────────────────────────────────────
  readonly columns = signal<MappedColumn[]>([]);
  protected readonly matchMode = signal<MatchMode>('upsert');
  protected readonly matchColumns = signal<string[]>([]);
  protected readonly allOrNothing = signal(false);
  protected readonly triggersOn = signal(false);
  protected readonly createMissing = signal(false);

  // ── The job ────────────────────────────────────────────────────────────────
  readonly job = signal<ImportJob | null>(null);
  readonly phase = signal<Phase>('setup');
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly notice = signal<string | null>(null);
  protected readonly preview = signal<ImportPreviewRow[]>([]);
  protected readonly masked = signal<string[]>([]);
  protected readonly counts = computed(() => countsOf(this.job()));
  protected readonly previewColumns = computed(() => {
    const names = new Set<string>();
    for (const row of this.preview()) {
      for (const key of Object.keys((row.mapped ?? {}) as Record<string, unknown>)) names.add(key);
    }
    return [...names];
  });
  protected readonly errorFileUrl = computed(() => {
    const job = this.job();
    return job ? this.jobs.errorFileUrl(job.entity_logicalname, job.id) : null;
  });

  /** Why the file cannot be sent yet, as a catalog key, or null. */
  protected readonly blocker = computed<string | null>(() => {
    if (!this.schema()) return 'importJob.blocker.entity';
    if (!this.file()) return 'importJob.blocker.file';
    if (this.parsed()?.unterminatedQuoteRow != null) return 'importJob.blocker.file';
    if (!this.isSpreadsheet() && !this.columns().some(c => c.target)) return 'importJob.blocker.mapping';
    return null;
  });

  // ── Entity ─────────────────────────────────────────────────────────────────

  async loadEntity(): Promise<void> {
    const entity = this.entity().trim();
    if (!entity) return;
    this.error.set(null);
    this.busy.set(true);
    try {
      const [schema, recent] = await Promise.all([
        firstValueFrom(this.schemas.schema(entity)),
        firstValueFrom(this.jobs.list(entity)),
      ]);
      this.schema.set(schema);
      this.recent.set(recent);
      this.remap();
    } catch (e) {
      this.schema.set(null);
      this.error.set(this.message('importJob.error.entity', e));
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
    this.file.set(new Blob([bytes as BlobPart]));
    this.job.set(null);
    this.phase.set('setup');
    if (name.toLowerCase().endsWith('.xlsx')) {
      // A workbook is read on the server; it maps column to field by name.
      this.encoding.set(null);
      this.parsed.set(null);
      this.columns.set([]);
      return;
    }
    const decoded = decodeCsvBytes(bytes);
    this.encoding.set(decoded.encoding);
    this.parsed.set(parseCsv(decoded.text, { maxRows: CLIENT_PREVIEW_ROWS }));
    this.remap();
  }

  /** Matches the file's columns to fields by name. */
  private remap(): void {
    const parsed = this.parsed();
    if (!parsed) return;
    this.columns.set(
      autoMatchColumns(parsed.headers, this.fields(), parsed.rows.slice(0, 20)).map(c => ({
        source: c.source,
        target: c.target,
        confidence: null,
      })),
    );
  }

  protected setTarget(source: string, target: string): void {
    this.columns.update(cols => cols.map(c => (c.source === source ? { ...c, target: target || null, confidence: null } : c)));
  }

  protected toggleMatchColumn(field: string, on: boolean): void {
    this.matchColumns.update(list => (on ? [...new Set([...list, field])] : list.filter(f => f !== field)));
  }

  protected setMatchMode(value: string): void {
    this.matchMode.set(value as MatchMode);
  }

  /** A confidence as a badge level. */
  protected confidenceLevel(value: number): 'high' | 'medium' | 'low' {
    return value >= 0.8 ? 'high' : value >= 0.5 ? 'medium' : 'low';
  }

  protected percent(value: number): number {
    return Math.round(value * 100);
  }

  private options(): ImportOptionsBody {
    const rules = this.columns()
      .filter(c => c.target)
      .map(c => ({ source: c.source, target: c.target as string }));
    return {
      mapping: rules.length || this.createMissing() ? { columns: rules, create_missing: this.createMissing() } : {},
      match_mode: this.matchMode(),
      match_columns: this.matchColumns(),
      all_or_nothing: this.allOrNothing(),
      triggers_on: this.triggersOn(),
    };
  }

  // ── The job ────────────────────────────────────────────────────────────────

  /** Sends the file and runs the check (a dry run): nothing is written. */
  async upload(): Promise<void> {
    const schema = this.schema();
    const file = this.file();
    if (this.blocker() || this.busy() || !schema || !file) return;
    this.busy.set(true);
    this.error.set(null);
    this.phase.set('working');
    try {
      const created = await firstValueFrom(
        this.jobs.upload(schema.name, file, this.fileName() ?? 'import.csv', this.options(), true),
      );
      if (created.existing) this.notice.set(this.lang.translate('importJob.existing'));
      await this.afterCheck(await this.waitFor(created.job_id, ['validated', 'failed', 'applied', 'undone']));
    } catch (e) {
      this.phase.set('setup');
      this.error.set(this.message('importJob.error.upload', e));
    } finally {
      this.busy.set(false);
    }
  }

  /** Asks the mapping agent for each column's field. */
  async propose(): Promise<void> {
    const job = this.job();
    if (!job || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      const proposed = await firstValueFrom(this.jobs.proposeMapping(job.id));
      if (proposed === null) {
        this.notice.set(this.lang.translate('importJob.proposeUnavailable'));
        return;
      }
      const known = new Set(this.fields().map(f => f.name));
      const bySource = new Map(proposed.map(p => [p.column, p]));
      const sources = this.columns().length ? this.columns().map(c => c.source) : proposed.map(p => p.column);
      this.columns.set(
        sources.map(source => {
          const p = bySource.get(source);
          const target = p?.attribute && known.has(p.attribute) ? p.attribute : null;
          return { source, target, confidence: p ? p.confidence : null };
        }),
      );
    } catch (e) {
      this.error.set(this.message('importJob.error.propose', e));
    } finally {
      this.busy.set(false);
    }
  }

  /** Saves the mapping and options and checks the file again. */
  async recheck(): Promise<void> {
    const job = this.job();
    if (!job || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.phase.set('working');
    try {
      await firstValueFrom(this.jobs.update(job.entity_logicalname, job.id, this.options()));
      await firstValueFrom(this.jobs.dryRun(job.entity_logicalname, job.id));
      await this.afterCheck(await this.waitFor(job.id, ['validated', 'failed']));
    } catch (e) {
      this.phase.set('checked');
      this.error.set(this.message('importJob.error.check', e));
    } finally {
      this.busy.set(false);
    }
  }

  /** Applies the checked import, or asks for approval when its policy wants it. */
  async apply(): Promise<void> {
    const job = this.job();
    if (!job || this.busy() || this.phase() !== 'checked') return;
    this.busy.set(true);
    this.error.set(null);
    try {
      const accepted = await firstValueFrom(this.jobs.apply(job.entity_logicalname, job.id));
      if (accepted.status === 'awaiting_approval') {
        this.phase.set('awaiting');
        this.notice.set(this.lang.translate('importJob.awaitingApproval'));
        return;
      }
      this.phase.set('working');
      const done = await this.waitFor(job.id, ['applied', 'failed']);
      this.phase.set(done.status === 'applied' ? 'done' : 'failed');
      await this.refreshRecent();
    } catch (e) {
      this.phase.set('checked');
      this.error.set(this.message('importJob.error.apply', e));
    } finally {
      this.busy.set(false);
    }
  }

  /** Undoes an applied import; records changed since stay and are counted. */
  async undo(): Promise<void> {
    const job = this.job();
    if (!job || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      await firstValueFrom(this.jobs.undo(job.entity_logicalname, job.id));
      this.phase.set('working');
      const done = await this.waitFor(job.id, ['undone', 'failed']);
      this.phase.set(done.status === 'undone' ? 'undone' : 'failed');
      await this.refreshRecent();
    } catch (e) {
      this.phase.set('done');
      this.error.set(this.message('importJob.error.undo', e));
    } finally {
      this.busy.set(false);
    }
  }

  /** Cancels an import that has not started applying. */
  async cancel(): Promise<void> {
    const job = this.job();
    if (!job || this.busy()) return;
    try {
      await firstValueFrom(this.jobs.cancel(job.entity_logicalname, job.id));
      this.job.set(null);
      this.phase.set('setup');
      await this.refreshRecent();
    } catch (e) {
      this.error.set(this.message('importJob.error.cancel', e));
    }
  }

  /** Re-reads the job until its status is one of `done`. */
  private async waitFor(id: string, done: string[]): Promise<ImportJob> {
    const entity = this.schema()?.name ?? this.entity().trim();
    let job = await firstValueFrom(this.jobs.get(entity, id));
    for (let i = 0; i < POLL_TRIES && !done.includes(job.status); i++) {
      this.job.set(job);
      await new Promise(resolve => setTimeout(resolve, POLL_MS));
      job = await firstValueFrom(this.jobs.get(entity, id));
    }
    this.job.set(job);
    return job;
  }

  private async afterCheck(job: ImportJob): Promise<void> {
    if (job.status === 'failed') {
      this.phase.set('failed');
      return;
    }
    const preview = await firstValueFrom(this.jobs.preview(job.entity_logicalname, job.id));
    this.preview.set(preview.rows);
    this.masked.set(preview.masked);
    this.phase.set(job.status === 'applied' ? 'done' : job.status === 'undone' ? 'undone' : 'checked');
  }

  private async refreshRecent(): Promise<void> {
    const entity = this.schema()?.name;
    if (!entity) return;
    try {
      this.recent.set(await firstValueFrom(this.jobs.list(entity)));
    } catch {
      // The list is a convenience; the import's own state is already shown.
    }
  }

  protected cell(row: ImportPreviewRow, column: string): string {
    const value = ((row.mapped ?? {}) as Record<string, unknown>)[column];
    if (value === null || value === undefined) return '';
    return typeof value === 'string' ? value : JSON.stringify(value);
  }

  protected rowErrors(row: ImportPreviewRow): string {
    const errors = ((row.error ?? {}) as { errors?: { field: string; code: string }[] }).errors ?? [];
    return errors
      .map(e => `${e.field ? e.field + ': ' : ''}${this.lang.translate(`importJob.code.${e.code}`)}`)
      .join('; ');
  }

  private message(key: string, e: unknown): string {
    const err = e as ApiError | undefined;
    if (err?.status === 403) return this.lang.translate('importJob.error.forbidden');
    if (err?.status === 409) return this.lang.translate('importJob.error.conflict', { message: err.message ?? '' });
    return this.lang.translate(key, { message: err?.message ?? String(e) });
  }
}
