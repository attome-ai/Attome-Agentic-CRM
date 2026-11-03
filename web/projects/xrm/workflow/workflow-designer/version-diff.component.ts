import { ChangeDetectionStrategy, Component, OnInit, computed, inject, input, output, signal } from '@angular/core';
import { ApiError, TranslatePipe } from '@attome/base';
import { type GraphDoc, type GraphDocEdge, type GraphDocNode, edgeKey } from '@attome/xrm/canvas';

import { type VersionSummary, WorkflowAdminService } from '../services/workflow-admin.service';

/** One setting that differs between two versions of a node. */
export interface SettingChange { key: string; before: unknown; after: unknown }
export interface NodeChange { id: string; type: string; typeBefore: string | null; settings: SettingChange[] }

export interface GraphDiff {
  added: GraphDocNode[];
  removed: GraphDocNode[];
  changed: NodeChange[];
  edgesAdded: GraphDocEdge[];
  edgesRemoved: GraphDocEdge[];
}

/** A value's text with its object keys sorted, so key order is no difference. Pure. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_k, v: unknown) => {
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      const o = v as Record<string, unknown>;
      return Object.fromEntries(Object.keys(o).sort().map(k => [k, o[k]]));
    }
    return v;
  }) ?? '';
}

/**
 * M2-T4 — what changed from `before` to `after`: nodes added and removed,
 * nodes whose type or settings changed, and connections. Moving a node on the
 * canvas, groups and notes change nothing a flow does, so they are no
 * difference. Pure.
 */
export function diffGraphs(before: GraphDoc, after: GraphDoc): GraphDiff {
  const old = new Map(before.nodes.map(n => [n.id, n]));
  const now = new Map(after.nodes.map(n => [n.id, n]));
  const changed: NodeChange[] = [];
  for (const node of after.nodes) {
    const prev = old.get(node.id);
    if (!prev) continue;
    const keys = [...new Set([...Object.keys(prev.config ?? {}), ...Object.keys(node.config ?? {})])].sort();
    const settings = keys.flatMap(key => {
      const was = prev.config?.[key];
      const is = node.config?.[key];
      return canonical(was) === canonical(is) ? [] : [{ key, before: was, after: is }];
    });
    if (settings.length || prev.type !== node.type) {
      changed.push({ id: node.id, type: node.type, typeBefore: prev.type === node.type ? null : prev.type, settings });
    }
  }
  const oldEdges = new Set(before.edges.map(edgeKey));
  const newEdges = new Set(after.edges.map(edgeKey));
  return {
    added: after.nodes.filter(n => !old.has(n.id)),
    removed: before.nodes.filter(n => !now.has(n.id)),
    changed,
    edgesAdded: after.edges.filter(e => !oldEdges.has(edgeKey(e))),
    edgesRemoved: before.edges.filter(e => !newEdges.has(edgeKey(e))),
  };
}

/** The version to compare with first: the one before this, else any other. Pure. */
export function defaultBase(versions: readonly VersionSummary[], current: string): VersionSummary | null {
  const here = versions.find(v => v.id === current);
  const others = versions.filter(v => v.id !== current).sort((a, b) => b.version_number - a.version_number);
  if (!here) return others[0] ?? null;
  return others.find(v => v.version_number < here.version_number) ?? others[0] ?? null;
}

/**
 * M2-T4 — compares this flow's graph, as it stands in the designer, with
 * another version of the flow.
 */
@Component({
  selector: 'xrm-version-diff',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="vd" data-testid="version-diff" [attr.aria-label]="'workflowDesigner.diff.title' | translate">
      <div class="vd-head">
        <h3>{{ 'workflowDesigner.diff.title' | translate }}</h3>
        @if (others().length) {
          <label for="vd-base">{{ 'workflowDesigner.diff.against' | translate }}</label>
          <select id="vd-base" data-testid="vd-base" (change)="pick(valueOf($event))">
            @for (v of others(); track v.id) {
              <option [value]="v.id" [selected]="v.id === baseId()">{{ 'workflowDesigner.versionN' | translate: { n: v.version_number } }}</option>
            }
          </select>
        }
        <button type="button" class="vd-close" data-testid="vd-close" (click)="closed.emit()">{{ 'workflowDesigner.diff.close' | translate }}</button>
      </div>
      @if (error(); as e) {
        <p class="vd-error" role="alert">{{ e }}</p>
      } @else if (others().length === 0 && !loading()) {
        <p class="vd-muted" data-testid="vd-only">{{ 'workflowDesigner.diff.onlyVersion' | translate }}</p>
      } @else if (diff(); as d) {
        @if (empty()) {
          <p class="vd-muted" data-testid="vd-same">{{ 'workflowDesigner.diff.same' | translate }}</p>
        }
        @if (d.added.length) {
          <h4>{{ 'workflowDesigner.diff.added' | translate }}</h4>
          <ul data-testid="vd-added">@for (n of d.added; track n.id) { <li>{{ labelOf()(n.type) }} <bdi dir="ltr">{{ n.id }}</bdi></li> }</ul>
        }
        @if (d.removed.length) {
          <h4>{{ 'workflowDesigner.diff.removed' | translate }}</h4>
          <ul data-testid="vd-removed">@for (n of d.removed; track n.id) { <li>{{ labelOf()(n.type) }} <bdi dir="ltr">{{ n.id }}</bdi></li> }</ul>
        }
        @if (d.changed.length) {
          <h4>{{ 'workflowDesigner.diff.changed' | translate }}</h4>
          <ul data-testid="vd-changed">
            @for (c of d.changed; track c.id) {
              <li>
                {{ labelOf()(c.type) }} <bdi dir="ltr">{{ c.id }}</bdi>
                @if (c.typeBefore) { <span class="vd-muted"> {{ 'workflowDesigner.diff.typeWas' | translate: { type: labelOf()(c.typeBefore) } }}</span> }
                <ul>
                  @for (s of c.settings; track s.key) {
                    <li data-testid="vd-setting"><bdi dir="ltr"><code>{{ s.key }}</code>: {{ show(s.before) }} → {{ show(s.after) }}</bdi></li>
                  }
                </ul>
              </li>
            }
          </ul>
        }
        @if (d.edgesAdded.length) {
          <h4>{{ 'workflowDesigner.diff.edgesAdded' | translate }}</h4>
          <ul data-testid="vd-edges-added">@for (e of d.edgesAdded; track $index) { <li><bdi dir="ltr">{{ edge(e) }}</bdi></li> }</ul>
        }
        @if (d.edgesRemoved.length) {
          <h4>{{ 'workflowDesigner.diff.edgesRemoved' | translate }}</h4>
          <ul data-testid="vd-edges-removed">@for (e of d.edgesRemoved; track $index) { <li><bdi dir="ltr">{{ edge(e) }}</bdi></li> }</ul>
        }
      } @else {
        <p class="vd-muted">{{ 'workflowDesigner.loading' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .vd { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; display: grid; gap: .375rem; font-size: .8125rem; }
    .vd-head { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    .vd h3 { margin: 0; font-size: 1rem; }
    .vd h4 { margin: .25rem 0 0; font-size: .8125rem; }
    .vd ul { margin: 0; padding-inline-start: 1.25rem; }
    .vd-close { margin-inline-start: auto; }
    .vd-muted { color: var(--color-text-secondary, #666); margin: 0; }
    .vd-error { color: var(--color-danger, #c53030); margin: 0; }
  `],
})
export class VersionDiffComponent implements OnInit {
  readonly definitionId = input.required<string>();
  readonly versionId = input.required<string>();
  /** The graph as it stands in the designer, saved or not. */
  readonly doc = input.required<GraphDoc>();
  readonly labelOf = input<(type: string) => string>(t => t);
  readonly closed = output<void>();

  private readonly svc = inject(WorkflowAdminService);

  readonly others = signal<VersionSummary[]>([]);
  readonly baseId = signal<string | null>(null);
  readonly base = signal<GraphDoc | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  readonly diff = computed(() => {
    const base = this.base();
    return base ? diffGraphs(base, this.doc()) : null;
  });
  readonly empty = computed(() => {
    const d = this.diff();
    return !!d && !d.added.length && !d.removed.length && !d.changed.length && !d.edgesAdded.length && !d.edgesRemoved.length;
  });

  ngOnInit(): void {
    this.svc.getDefinition(this.definitionId()).subscribe({
      next: detail => {
        const current = this.versionId();
        this.others.set(detail.versions.filter(v => v.id !== current).sort((a, b) => b.version_number - a.version_number));
        const first = defaultBase(detail.versions, current);
        if (first) this.pick(first.id);
        else this.loading.set(false);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  pick(id: string): void {
    this.baseId.set(id);
    this.base.set(null);
    this.error.set(null);
    this.svc.getVersion(this.definitionId(), id).subscribe({
      next: v => {
        // A later choice wins, whichever answer arrives first.
        if (this.baseId() !== id) return;
        const g = (v.graph && typeof v.graph === 'object' ? v.graph : {}) as Partial<GraphDoc>;
        this.base.set({ nodes: Array.isArray(g.nodes) ? g.nodes : [], edges: Array.isArray(g.edges) ? g.edges : [] });
        this.loading.set(false);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  show(value: unknown): string {
    return value === undefined ? '—' : JSON.stringify(value);
  }

  edge(e: GraphDocEdge): string {
    return `${e.from_node}.${e.from_port} → ${e.to_node}.${e.to_port}`;
  }

  protected valueOf(event: Event): string {
    return (event.target as HTMLSelectElement).value;
  }
}
