import { inject, Injectable } from '@angular/core';
import { ApiComponents, ApiService } from '@attome/base';
import { map, Observable } from 'rxjs';

export type ImportJob = ApiComponents['schemas']['ImportJobView'];
export type ImportCreated = ApiComponents['schemas']['ImportCreated'];
export type ImportAccepted = ApiComponents['schemas']['ImportAccepted'];
export type ImportPreview = ApiComponents['schemas']['ImportPreview'];
export type ImportPreviewRow = ApiComponents['schemas']['PreviewRow'];

/** One column rule of an import's mapping (`attome_records::import_validate`). */
export interface ImportColumnRule {
  source: string;
  target: string;
}

/** An import's mapping: column rules, and whether a missing lookup is created. */
export interface ImportMappingBody {
  columns: ImportColumnRule[];
  create_missing?: boolean;
}

/** The options an upload or an options change sends. */
export interface ImportOptionsBody {
  mapping: ImportMappingBody | Record<string, never>;
  match_mode: 'create' | 'update' | 'upsert';
  match_columns: string[];
  all_or_nothing: boolean;
  triggers_on: boolean;
}

/** One column as the mapping agent proposed it (`import.propose_mapping`). */
export interface ProposedColumn {
  column: string;
  attribute: string | null;
  transform: string | null;
  confidence: number;
}

/** The counts an import job keeps. */
export interface ImportCounts {
  staged?: number;
  create?: number;
  update?: number;
  skip?: number;
  invalid?: number;
  duplicates?: number;
  applied?: number;
  apply_failed?: number;
  error?: string;
  undo?: { reverted: number; skipped: number };
}

/** An import job's counts, typed (the wire type is an open object). */
export function countsOf(job: ImportJob | null): ImportCounts {
  return (job?.counts ?? {}) as unknown as ImportCounts;
}

/**
 * A23-T13 — every call the import wizard makes: the server-side import job
 * (`/api/v1/{entity}/imports`, `attome_document::import_routes`) and the
 * mapping agent. The file goes to the server as it is; the server stages,
 * checks and applies it, so there is no second import path in the browser.
 */
@Injectable({ providedIn: 'root' })
export class ImportJobService {
  private readonly api = inject(ApiService);

  private base(entity: string): string {
    return `/api/v1/${encodeURIComponent(entity)}/imports`;
  }

  /** Uploads `file` with `options`; `dry_run` stops the job after its check. */
  upload(entity: string, file: Blob, name: string, options: ImportOptionsBody, dryRun: boolean): Observable<ImportCreated> {
    const form = new FormData();
    form.append('file', file, name);
    form.append('options', JSON.stringify({ ...options, dry_run: dryRun }));
    return this.api.post<ImportCreated>(this.base(entity), form);
  }

  list(entity: string): Observable<ImportJob[]> {
    return this.api
      .get<{ items: ImportJob[] }>(this.base(entity), { page_size: '20' })
      .pipe(map(page => page.items));
  }

  get(entity: string, id: string): Observable<ImportJob> {
    return this.api.get<ImportJob>(`${this.base(entity)}/${id}`);
  }

  update(entity: string, id: string, options: ImportOptionsBody): Observable<ImportJob> {
    return this.api.patch<ImportJob>(`${this.base(entity)}/${id}`, options);
  }

  dryRun(entity: string, id: string): Observable<ImportAccepted> {
    return this.api.post<ImportAccepted>(`${this.base(entity)}/${id}/dry-run`, {});
  }

  apply(entity: string, id: string): Observable<ImportAccepted> {
    return this.api.post<ImportAccepted>(`${this.base(entity)}/${id}/apply`, {});
  }

  undo(entity: string, id: string): Observable<ImportAccepted> {
    return this.api.post<ImportAccepted>(`${this.base(entity)}/${id}/undo`, {});
  }

  cancel(entity: string, id: string): Observable<ImportAccepted> {
    return this.api.post<ImportAccepted>(`${this.base(entity)}/${id}/cancel`, {});
  }

  preview(entity: string, id: string, limit = 50): Observable<ImportPreview> {
    return this.api.get<ImportPreview>(`${this.base(entity)}/${id}/preview`, { limit: String(limit) });
  }

  /** Where the error file downloads from (the session cookie authorizes it). */
  errorFileUrl(entity: string, id: string): string {
    return `${this.base(entity)}/${id}/errors`;
  }

  /** The mapping agent's proposal, or null when the action did not run. */
  proposeMapping(jobId: string): Observable<ProposedColumn[] | null> {
    return this.api
      .post<{ status: string; result?: { columns?: ProposedColumn[] } }>(
        `/api/v1/actions/${encodeURIComponent('import.propose_mapping')}/invoke`,
        { args: { job_id: jobId } },
      )
      .pipe(map(outcome => (outcome.status === 'completed' ? (outcome.result?.columns ?? []) : null)));
  }
}
