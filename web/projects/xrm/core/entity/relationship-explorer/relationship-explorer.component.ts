import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiService, LangService, TranslatePipe } from '@attome/base';
import type { ApiComponents } from '@attome/base';
import { entityFormRoute } from '../services/entity-url.utils';

/** `POST /api/v1/graph/traverse`'s wire shapes, straight from the generated
 * contract — M38 Phase 1's bounded, permission-per-hop traversal. */
export type TraverseRequest = ApiComponents['schemas']['TraverseRequest'];
export type TraverseResponse = ApiComponents['schemas']['TraverseResponse'];
export type GraphEdge = ApiComponents['schemas']['GraphEdge'];
export type GraphDirection = ApiComponents['schemas']['Direction'];
// `GraphNode` has no standalone `#/components/schemas/GraphNode` entry — it
// is never used outside `PaginatedResponse<GraphNode>` on the Rust side, so
// utoipa inlines its shape into the generated `PaginatedResponse_GraphNode`
// rather than emitting a separate named schema. Derived structurally instead
// of assumed, so a real schema drift breaks this at compile time.
export type GraphNode = TraverseResponse['nodes']['items'][number];

/** One edge, resolved for display: does the caller's own current record sit
 * on the `from` or `to` side, and where does the "explore this node" click
 * lead. */
interface DisplayEdge extends GraphEdge {
  key: string;
}

/** A7-T5: `POST /api/v1/graph/paths`'s answer. */
export interface PathsResponse {
  paths: GraphEdge[][];
  truncated: boolean;
}

/** One node of the diagram's ring around the record. */
export interface RingNode {
  key: string;
  node: { entity: string; id: string };
  label: string;
  x: number;
  y: number;
}

/** `n` points evenly round a circle of `radius` at (`cx`, `cy`), the first at the top. Pure. */
export function ringLayout(n: number, radius: number, cx: number, cy: number): { x: number; y: number }[] {
  return Array.from({ length: n }, (_, i) => {
    const angle = -Math.PI / 2 + (2 * Math.PI * i) / Math.max(n, 1);
    return { x: Math.round(cx + radius * Math.cos(angle)), y: Math.round(cy + radius * Math.sin(angle)) };
  });
}

/** A path as the entities it passes and the field it crosses each time, from `start`. Pure. */
export function pathSteps(path: GraphEdge[], start: { entity: string; id: string }): { entity: string; via: string | null }[] {
  const steps: { entity: string; via: string | null }[] = [{ entity: start.entity, via: null }];
  let here = start;
  for (const e of path) {
    const forward = e.from_entity === here.entity && e.from_id === here.id;
    const next = forward ? { entity: e.to_entity, id: e.to_id } : { entity: e.from_entity, id: e.from_id };
    const field = e.edge_type.includes(':') ? e.edge_type.slice(e.edge_type.indexOf(':') + 1) : e.edge_type;
    steps[steps.length - 1].via = field;
    steps.push({ entity: next.entity, via: null });
    here = next;
  }
  return steps;
}

/** The most records the diagram's ring shows. */
export const RING_MAX = 12;

/**
 * The relationship explorer panel (M38 Phase 1's Angular checklist item) —
 * an entity-form tab that calls the traversal endpoint and lists what it
 * found, letting a user jump to any connected record.
 *
 * **Nothing here re-decides visibility.** Every node and edge rendered here
 * already passed the backend's permission-per-hop check
 * (`attome_search::graph::walk`) — this component has no notion of "hidden" at
 * all, because a hidden node is never in the response to begin with. That is
 * the property the backend's hidden-intermediate-node test pins, and this
 * panel inherits it for free by never second-guessing what the API returned.
 */
@Component({
  selector: 'xrm-relationship-explorer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [CommonModule, FormsModule, TranslatePipe],
  styleUrls: ['./relationship-explorer.component.css'],
  templateUrl: './relationship-explorer.component.html',
})
export class RelationshipExplorerComponent {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();

  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly lang = inject(LangService);

  /** A7-T5: the diagram's square size and centre. */
  readonly size = 360;
  readonly center = 180;
  /** A7-T5: the other record of the path search. */
  readonly targetEntity = signal('');
  readonly targetId = signal('');
  readonly paths = signal<PathsResponse | null>(null);
  readonly pathsLoading = signal(false);

  readonly direction = signal<GraphDirection>('both');
  readonly maxDepth = signal(2);

  readonly loading = signal(false);
  readonly errorMessage = signal<string | null>(null);
  readonly response = signal<TraverseResponse | null>(null);

  readonly nodeCount = computed(() => this.response()?.nodes.total ?? 0);
  readonly truncated = computed(() => this.response()?.truncated ?? false);

  /** Edges grouped under a stable key for `@for`'s `track`. */
  readonly edges = computed<DisplayEdge[]>(() => {
    const res = this.response();
    if (!res) return [];
    return res.edges.map((e, i) => ({ ...e, key: `${e.edge_type}:${e.from_id}:${e.to_id}:${i}` }));
  });

  /** A7-T5: the records the record links to directly, round it. */
  readonly ring = computed<RingNode[]>(() => {
    const seen = new Map<string, { node: { entity: string; id: string }; label: string }>();
    for (const e of this.edges()) {
      const touches = (e.from_entity === this.entityName() && e.from_id === this.recordId())
        || (e.to_entity === this.entityName() && e.to_id === this.recordId());
      if (!touches) continue;
      const node = this.otherNode(e);
      const key = `${node.entity}:${node.id}`;
      if (!seen.has(key)) seen.set(key, { node, label: this.edgeFieldLabel(e.edge_type) });
    }
    const list = [...seen.entries()].slice(0, RING_MAX);
    const points = ringLayout(list.length, 130, this.center, this.center);
    return list.map(([key, v], i) => ({ key, node: v.node, label: v.label, x: points[i].x, y: points[i].y }));
  });

  constructor() {
    effect(() => {
      const entity = this.entityName();
      const id = this.recordId();
      untracked(() => {
        if (entity && id) this.explore();
      });
    });
  }

  explore(): void {
    const entity = this.entityName();
    const id = this.recordId();
    if (!entity || !id) return;

    this.loading.set(true);
    this.errorMessage.set(null);

    const body: TraverseRequest = {
      start: { entity, id },
      direction: this.direction(),
      max_depth: this.maxDepth(),
      limit: 100,
    };

    this.api.post<TraverseResponse>('/api/v1/graph/traverse', body).subscribe({
      next: (res) => {
        this.response.set(res);
        this.loading.set(false);
      },
      error: (err) => {
        this.response.set(null);
        this.loading.set(false);
        this.errorMessage.set(err?.message || this.lang.translate('relationshipExplorer.failed'));
      },
    });
  }

  /** Whether the current record is the `from` side of this edge (its `to`
   * side is the "other" node to navigate to) — an edge can point either way
   * relative to the record whose panel this is. */
  isOutgoingFromCurrent(edge: GraphEdge): boolean {
    return edge.from_entity === this.entityName() && edge.from_id === this.recordId();
  }

  otherNode(edge: GraphEdge): { entity: string; id: string } {
    return this.isOutgoingFromCurrent(edge)
      ? { entity: edge.to_entity, id: edge.to_id }
      : { entity: edge.from_entity, id: edge.from_id };
  }

  openNode(node: { entity: string; id: string }): void {
    this.router.navigate(entityFormRoute(node.entity), { queryParams: { id: node.id } });
  }

  /** `"lookup:owner_id"` → `"owner_id"`; `"relationship:reports_to"` →
   * `"reports_to"`; `"hierarchy:parent_account_id"` → `"parent_account_id"`
   * — the label a user reads, with the source kept as a separate badge. */
  edgeFieldLabel(edgeType: string): string {
    const i = edgeType.indexOf(':');
    return i === -1 ? edgeType : edgeType.slice(i + 1);
  }

  value(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  /** A7-T5: how this record connects to the target record. */
  findPaths(): void {
    const entity = this.targetEntity().trim();
    const id = this.targetId().trim();
    if (!entity || !id) return;
    this.pathsLoading.set(true);
    this.api.post<PathsResponse>('/api/v1/graph/paths', {
      from: { entity: this.entityName(), id: this.recordId() },
      to: { entity, id },
    }).subscribe({
      next: (res) => {
        this.paths.set(res);
        this.pathsLoading.set(false);
      },
      error: (err) => {
        this.paths.set(null);
        this.pathsLoading.set(false);
        this.errorMessage.set(err?.message || this.lang.translate('relationshipExplorer.failed'));
      },
    });
  }

  pathSteps(path: GraphEdge[]): { entity: string; via: string | null }[] {
    return pathSteps(path, { entity: this.entityName(), id: this.recordId() });
  }

  edgeSourceLabel(edgeType: string): string {
    const i = edgeType.indexOf(':');
    return i === -1 ? edgeType : edgeType.slice(0, i);
  }
}
