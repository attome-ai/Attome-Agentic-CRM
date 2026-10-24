import { inject, Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { ApiService } from '@attome/base';

/**
 * L5 lineage over `crates/engine/attome-api/src/lineage_admin.rs` and
 * `catalog_admin.rs`'s impact route: a walk from one node, two graph
 * versions compared, the cleanup list, and a draft change's impact.
 */

/** A node as the API names it (serde's external tagging of `NodeRef`). */
export type LineageNodeRef =
  | { Data: { entity: string; attribute?: string | null } }
  | { Definition: { kind: string; id: string } };

export interface LineageNode {
  /** `entity:<e>[.<a>]` or `<kind>:<id>`. */
  key: string;
  node: LineageNodeRef;
  label: string;
  depth: number;
  /** A definition that uses a personal attribute. */
  reads_personal: boolean;
}

/** `from` uses `to`. */
export interface LineageEdge {
  from: string;
  to: string;
  edge_kind: string;
  confidence: string;
}

export interface LineageGraph {
  nodes: LineageNode[];
  edges: LineageEdge[];
  /** Nodes the caller may not see, counted only. */
  hidden: number;
  truncated: boolean;
}

export interface LineageComparison {
  from: number;
  to: number;
  added: LineageEdge[];
  removed: LineageEdge[];
  truncated: boolean;
}

export interface LineageCleanup {
  dangling: LineageEdge[];
  cycles: string[][];
  unused_attributes: string[];
}

export interface ImpactAffected {
  from_kind: string;
  from_ref: string;
  from_label: string;
  depth: number;
  edge_kind: string;
  confidence: string;
  attribute_level: boolean;
  change: number;
}

export interface ImpactBreaking {
  from_kind: string;
  from_ref: string;
  from_label: string;
  edge_kind: string;
}

export interface ImpactReport {
  affected: ImpactAffected[];
  breaking: ImpactBreaking[];
  hidden: number;
}

/** What a draft change does to the field, as the impact route names it. */
export type ImpactChange = 'delete' | 'retype' | 'rename' | 'other';

export type LineageDirection = 'down' | 'up';

/** The most edges a walk follows (`graph::MAX_DEPTH`). */
export const LINEAGE_MAX_DEPTH = 10;

/** The definition kinds a walk can keep. */
export const LINEAGE_KINDS = ['workflow', 'query', 'metric', 'dashboard', 'agent', 'system'] as const;

export interface LineageWalk {
  direction?: LineageDirection;
  depth?: number;
  kinds?: readonly string[];
  version?: number | null;
}

@Injectable({ providedIn: 'root' })
export class LineageService {
  private readonly api = inject(ApiService);

  /** Walks from `kind`/`ref`: `entity` with `<entity>[.<attribute>]`, or a definition kind with its id. */
  walk(kind: string, ref: string, walk: LineageWalk = {}): Observable<LineageGraph> {
    const params: Record<string, string> = {};
    if (walk.direction) params['direction'] = walk.direction;
    if (walk.depth) params['depth'] = String(walk.depth);
    if (walk.kinds?.length) params['kinds'] = walk.kinds.join(',');
    if (walk.version !== null && walk.version !== undefined) params['version'] = String(walk.version);
    return this.api.get<LineageGraph>(
      `/api/v1/lineage/${encodeURIComponent(kind)}/${encodeURIComponent(ref)}`, params,
    );
  }

  compare(from: number, to: number): Observable<LineageComparison> {
    return this.api.get<LineageComparison>('/api/v1/lineage/compare', { from: String(from), to: String(to) });
  }

  cleanup(): Observable<LineageCleanup> {
    return this.api.get<LineageCleanup>('/api/v1/lineage/cleanup');
  }

  impact(entity: string, attribute: string | null, change: ImpactChange, depth?: number): Observable<ImpactReport> {
    const params: Record<string, string> = { entity, change };
    if (attribute) params['attribute'] = attribute;
    if (depth) params['depth'] = String(depth);
    return this.api.get<ImpactReport>('/api/v1/admin/lineage/impact', params);
  }
}
