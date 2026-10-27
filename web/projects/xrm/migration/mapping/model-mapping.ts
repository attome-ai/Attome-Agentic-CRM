import { Injectable, inject } from '@angular/core';
import { ApiService } from '@attome/base';
import type { Observable } from 'rxjs';

/**
 * A24-T3: a migration project's model mapping (`/api/v1/admin/migration-projects/{id}/model-mapping`):
 * each source entity and field and what it becomes here. The draft comes
 * from the server; the person edits it as a table and saves it.
 */
export type MapAction = 'map' | 'create' | 'skip';

export interface ValueMapping {
  source: string;
  target: string | null;
}

export interface AttributeMapping {
  source: string;
  source_label: string;
  source_type: string;
  action: MapAction;
  target: string;
  field_type: string;
  type_mismatch: boolean;
  lookup_target: string | null;
  choices: ValueMapping[];
}

export interface EntityMapping {
  source: string;
  source_label: string;
  action: MapAction;
  target: string;
  attributes: AttributeMapping[];
}

/** A source person and the user account here they become. */
export interface UserMapping {
  source: string;
  name: string;
  email: string | null;
  target: string | null;
}

export interface ModelMapping {
  entities: EntityMapping[];
  users: UserMapping[];
  roles: ValueMapping[];
}

/** A24-T4: one wave of a migration run. */
export interface MigrationWave {
  id: string;
  system: string;
  kind: 'full' | 'catch_up' | 'cut_over';
  since: string | null;
  status: 'queued' | 'running' | 'loaded' | 'failed';
  counts: { metadata_steps?: number; entities?: number; rows?: number; imports?: number };
  error: string | null;
  created_at: string;
  finished_at: string | null;
}

export interface MappingDoc {
  project_id: string;
  row_version: number;
  source_model: { entities: unknown[] };
  mapping: ModelMapping;
  problems: string[];
  updated_at: string;
}

/** The field types a created attribute can take. */
export const CREATE_TYPES = [
  'text', 'number', 'currency', 'date', 'date_time', 'time', 'bool', 'choice', 'lookup', 'file', 'image', 'rich_text',
] as const;

/** `mapping` with entity `e` changed. Pure. */
export function withEntity(mapping: ModelMapping, e: number, patch: Partial<EntityMapping>): ModelMapping {
  return { ...mapping, entities: mapping.entities.map((x, i) => (i === e ? { ...x, ...patch } : x)) };
}

/** `mapping` with attribute `a` of entity `e` changed. Pure. */
export function withAttribute(mapping: ModelMapping, e: number, a: number, patch: Partial<AttributeMapping>): ModelMapping {
  return withEntity(mapping, e, {
    attributes: mapping.entities[e].attributes.map((x, i) => (i === a ? { ...x, ...patch } : x)),
  });
}

/** The attributes several source fields go into: a merge, shown so it is deliberate. Pure. */
export function merges(entity: EntityMapping): Set<string> {
  const seen = new Map<string, number>();
  for (const a of entity.attributes) {
    if (a.action !== 'skip') seen.set(a.target, (seen.get(a.target) ?? 0) + 1);
  }
  return new Set([...seen].filter(([, n]) => n > 1).map(([t]) => t));
}

/** `mapping` with source person `u` becoming account `target` (empty: none). Pure. */
export function withUser(mapping: ModelMapping, u: number, target: string): ModelMapping {
  const t = target.trim();
  return { ...mapping, users: mapping.users.map((x, i) => (i === u ? { ...x, target: t || null } : x)) };
}

/** How many entities and fields each action covers. Pure. */
export function counts(mapping: ModelMapping): Record<MapAction, number> {
  const out: Record<MapAction, number> = { map: 0, create: 0, skip: 0 };
  for (const e of mapping.entities) {
    for (const a of e.attributes) out[e.action === 'skip' ? 'skip' : a.action] += 1;
  }
  return out;
}

@Injectable({ providedIn: 'root' })
export class ModelMappingService {
  private readonly api = inject(ApiService);

  private path(projectId: string): string {
    return `/api/v1/admin/migration-projects/${encodeURIComponent(projectId)}/model-mapping`;
  }

  get(projectId: string): Observable<MappingDoc> {
    return this.api.get<MappingDoc>(this.path(projectId));
  }

  draft(projectId: string, sourceModel: unknown): Observable<MappingDoc> {
    return this.api.post<MappingDoc>(`${this.path(projectId)}/draft`, { source_model: sourceModel });
  }

  /** The model of the integration system `system` (a migration source). */
  describe(projectId: string, system: string): Observable<{ kind: string; source_model: unknown }> {
    return this.api.post<{ kind: string; source_model: unknown }>(
      `/api/v1/admin/migration-projects/${encodeURIComponent(projectId)}/source-model`, { system });
  }

  /** A24-T4: the project's waves, newest first. */
  waves(projectId: string): Observable<{ items: MigrationWave[] }> {
    return this.api.get<{ items: MigrationWave[] }>(
      `/api/v1/admin/migration-projects/${encodeURIComponent(projectId)}/waves`);
  }

  /** A24-T4: queues the next wave (the cut-over when `cutOver`). */
  startWave(projectId: string, system: string, cutOver: boolean): Observable<MigrationWave> {
    return this.api.post<MigrationWave>(
      `/api/v1/admin/migration-projects/${encodeURIComponent(projectId)}/waves`, { system, cut_over: cutOver });
  }

  save(projectId: string, mapping: ModelMapping, rowVersion: number): Observable<MappingDoc> {
    return this.api.put<MappingDoc>(this.path(projectId), { mapping, row_version: rowVersion });
  }
}
