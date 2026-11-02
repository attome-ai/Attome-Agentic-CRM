import { inject, Injectable } from '@angular/core';
import { ApiComponents, LangService, SdkService } from '@attome/base';
import type { EntitySchema } from '@attome/xrm';
import { firstValueFrom, map, Observable } from 'rxjs';
import type { DataMappingField } from './csv-mapping';

export type MigrationProject = ApiComponents['schemas']['MigrationProjectRow'];
export type MigrationRunListItem = ApiComponents['schemas']['MigrationRunListItem'];
export type StagedImportResponse = ApiComponents['schemas']['StagedImportResponse'];

/** `validation_report` is typed as a bare object on the wire; this is its item shape
 * (`bulk.rs::staged_import`: `{index, status, error?}`). */
export interface ValidationReportItem {
  index: number;
  status: string;
  error?: string;
}

export type MigrationRunDetail = Omit<ApiComponents['schemas']['MigrationRunDetail'], 'validation_report'> & {
  validation_report: ValidationReportItem[];
};

export interface DataMapping {
  id: string;
  name: string;
  target_entity: string;
  source_kind: string;
  fields: DataMappingField[];
}

/**
 * U11 / D-606 — every server call the CSV import makes, each a thin wrapper
 * over a route that already exists: the schema read, D-408's mapping CRUD
 * (`/api/v1/admin/data/mappings`), M17's migration projects and runs, and
 * the staged import itself. Nothing here writes a record directly.
 */
@Injectable({ providedIn: 'root' })
export class CsvImportService {
  private readonly sdk = inject(SdkService);
  private readonly lang = inject(LangService);

  schema(entity: string): Observable<EntitySchema> {
    return this.sdk.get<EntitySchema>(`/api/v1/schema/${encodeURIComponent(entity)}`, { query: {
      locale: this.lang.intlLocale(),
    } });
  }

  listMappings(entity: string): Observable<DataMapping[]> {
    return this.sdk
      .get<{ items: DataMapping[] }>('/api/v1/admin/data/mappings', { query: { target_entity: entity, page_size: '200' } })
      .pipe(map(page => page.items));
  }

  createMapping(body: { name: string; target_entity: string; fields: DataMappingField[] }): Observable<DataMapping> {
    return this.sdk.post<DataMapping>('/api/v1/admin/data/mappings', { body: { ...body, source_kind: 'csv' } });
  }

  /** CSV projects for `entity`, newest first — the ones an import can resume. */
  listProjects(entity: string): Observable<MigrationProject[]> {
    return this.sdk
      .get<{ items: MigrationProject[] }>('/api/v1/admin/migration-projects', { query: {
        target_entity: entity,
        page_size: '200',
      } })
      .pipe(map(page => page.items.filter(p => p.source_kind === 'csv' && p.status !== 'archived')));
  }

  createProject(body: {
    name: string;
    target_entity: string;
    mapping_ref: string;
    source_ref: string;
  }): Observable<MigrationProject> {
    return this.sdk.post<MigrationProject>('/api/v1/admin/migration-projects', { body: { ...body, source_kind: 'csv' } });
  }

  completeProject(projectId: string): Observable<MigrationProject> {
    return this.sdk.put<MigrationProject>(`/api/v1/admin/migration-projects/${projectId}`, { body: { status: 'completed' } });
  }

  stage(entity: string, body: object, idempotencyKey?: string): Promise<StagedImportResponse> {
    return firstValueFrom(
      this.sdk.post<StagedImportResponse>(`/api/v1/${encodeURIComponent(entity)}/staged-import`, { body }, { idempotencyKey }),
    );
  }

  linkRun(projectId: string, stagedImportId: string, idempotencyKey: string): Promise<MigrationRunDetail> {
    return firstValueFrom(
      this.sdk.post<MigrationRunDetail>(
        `/api/v1/admin/migration-projects/${projectId}/runs`,
        { body: { staged_import_id: stagedImportId } },
        { idempotencyKey },
      ),
    );
  }

  listRuns(projectId: string): Promise<MigrationRunListItem[]> {
    return firstValueFrom(
      this.sdk.getAllPages<MigrationRunListItem>(`/api/v1/admin/migration-projects/${projectId}/runs`),
    );
  }

  approve(entity: string, stagedImportId: string, idempotencyKey: string): Promise<StagedImportResponse> {
    return firstValueFrom(
      this.sdk.post<StagedImportResponse>(
        `/api/v1/${encodeURIComponent(entity)}/staged-import/${stagedImportId}/approve`,
        { body: {} },
        { idempotencyKey },
      ),
    );
  }
}
