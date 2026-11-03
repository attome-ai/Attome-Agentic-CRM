import {
  ChangeDetectionStrategy, Component, OnInit, computed, inject, input, signal, viewChild,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import {
  GraphCanvasComponent, type GraphDoc, type GraphDocNode, type GraphNodeKind,
} from '@attome/xrm/canvas';

import {
  NODE_TYPES, type NodeConfigField, type VersionDetail, WorkflowAdminService, nodeConfigFields, nodeTypeSpec,
} from '../services/workflow-admin.service';

/** The graph as the designer loads it: every node placed. Pure. */
export function placedGraph(graph: unknown): GraphDoc {
  const g = (graph && typeof graph === 'object' ? graph : {}) as Partial<GraphDoc>;
  const nodes = Array.isArray(g.nodes) ? g.nodes : [];
  return {
    ...g,
    nodes: nodes.map((n, i) => ({
      ...n,
      ports: n.ports && typeof n.ports.x === 'number' && typeof n.ports.y === 'number'
        ? n.ports : { ...(n.ports ?? {}), x: 40 + (i % 4) * 260, y: 40 + Math.floor(i / 4) * 180 },
    })),
    edges: Array.isArray(g.edges) ? g.edges : [],
  };
}

/** The node types matching a palette search, by type or label. Pure. */
export function paletteMatches(kinds: readonly GraphNodeKind[], query: string, labelOf: (t: string) => string): GraphNodeKind[] {
  const q = query.trim().toLocaleLowerCase();
  if (!q) return [...kinds];
  return kinds.filter(k => k.type.includes(q) || labelOf(k.type).toLocaleLowerCase().includes(q)
    || k.label.toLocaleLowerCase().includes(q));
}

/**
 * M2-T1 — the flow designer on the canvas engine (`@attome/xrm/canvas`'s
 * graph mode). The builder picks node types from the palette (searchable),
 * connects typed ports (an incompatible drop is refused with its reason while
 * dragging), groups nodes and adds notes, and sets the selected node's
 * settings in the form generated from its type (`nodeConfigFields`, the same
 * schema the classic editor uses). A sub-flow node opens the flow it runs.
 * Saving sends the whole graph (`PATCH …/versions/{id}`), as the classic
 * editor does; a published version is shown read-only.
 */
@Component({
  selector: 'attome-workflow-designer',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [GraphCanvasComponent, RouterLink, TranslatePipe],
  template: `
    <section class="wd">
      <header class="wd-head">
        <h2>{{ 'workflowDesigner.title' | translate }}</h2>
        @if (version(); as v) {
          <span class="wd-badge" data-testid="wd-status">{{ ('workflowDesigner.status.' + v.status) | translate }}</span>
          <span class="wd-muted">{{ 'workflowDesigner.versionN' | translate: { n: v.version_number } }}</span>
        }
        <a class="wd-classic" [routerLink]="['/xrm/workflow/definitions', definitionId(), 'versions', versionId()]">
          {{ 'workflowDesigner.classic' | translate }}</a>
      </header>
      @if (loading()) {
        <p class="wd-muted">{{ 'workflowDesigner.loading' | translate }}</p>
      } @else if (error(); as e) {
        <p class="wd-error" role="alert" data-testid="wd-error">{{ e }}</p>
      } @else {
        <div class="wd-body">
          @if (!readonly()) {
            <aside class="wd-palette" [attr.aria-label]="'workflowDesigner.palette' | translate">
              <label class="wd-label" for="wd-search">{{ 'workflowDesigner.search' | translate }}</label>
              <input id="wd-search" type="search" dir="auto" data-testid="wd-search" [value]="query()"
                     (input)="query.set(valueOf($event))" />
              <ul class="wd-types">
                @for (k of palette(); track k.type) {
                  <li><button type="button" data-testid="wd-add" [attr.data-type]="k.type" (click)="add(k.type)">{{ typeLabel(k.type) }}</button></li>
                } @empty {
                  <li class="wd-muted">{{ 'workflowDesigner.noMatch' | translate }}</li>
                }
              </ul>
            </aside>
          }
          <div class="wd-canvas">
            <xrm-graph-canvas [doc]="initial()" [kinds]="kinds" [readonly]="readonly()"
                              (changed)="current.set($event)" (nodeSelected)="selected.set($event)"
                              (save)="save()" (openSubflow)="openSubflow($event)" />
            @if (!readonly()) {
              <div class="wd-actions">
                @if (saveError(); as e) { <p class="wd-error" role="alert" data-testid="wd-save-error">{{ e }}</p> }
                <button type="button" data-testid="wd-publish" [disabled]="busy() || dirty()" (click)="publish()">{{ 'workflowDesigner.publish' | translate }}</button>
              </div>
            }
          </div>
          <aside class="wd-settings" [attr.aria-label]="'workflowDesigner.settings' | translate" data-testid="wd-settings">
            @if (selectedNode(); as sel) {
              <h3>{{ typeLabel(sel.node.type) }}</h3>
              <p class="wd-muted"><bdi dir="ltr">{{ sel.node.id }}</bdi></p>
              @for (f of fields(); track f.key) {
                <div class="wd-field">
                  <label [attr.for]="'wd-f-' + f.key">{{ f.label }}@if (f.required) {<span aria-hidden="true"> *</span>}</label>
                  @switch (f.kind) {
                    @case ('bool') {
                      <input type="checkbox" [id]="'wd-f-' + f.key" [checked]="configValue(f) === true" [disabled]="readonly()"
                             (change)="setConfig(f.key, checked($event))" />
                    }
                    @case ('select') {
                      <select [id]="'wd-f-' + f.key" [disabled]="readonly()" (change)="setConfig(f.key, valueOf($event) || undefined)">
                        <option value="" [selected]="configValue(f) === undefined">—</option>
                        @for (o of f.options ?? []; track o.value) {
                          <option [value]="o.value" [selected]="configValue(f) === o.value">{{ o.label }}</option>
                        }
                      </select>
                    }
                    @case ('textarea') {
                      <textarea [id]="'wd-f-' + f.key" dir="auto" [readOnly]="readonly()" [value]="text(f)"
                                (change)="setConfig(f.key, valueOf($event) || undefined)"></textarea>
                    }
                    @case ('json') {
                      <textarea [id]="'wd-f-' + f.key" dir="ltr" class="wd-json" [readOnly]="readonly()" [value]="json(f)"
                                [attr.data-field]="f.key" (change)="setJson(f.key, $event)"></textarea>
                      @if (jsonErrors()[f.key]) { <p class="wd-error" role="alert">{{ 'workflowDesigner.badJson' | translate }}</p> }
                    }
                    @case ('number') {
                      <input type="number" [id]="'wd-f-' + f.key" [readOnly]="readonly()" [value]="text(f)"
                             [placeholder]="placeholderOf(f)" (change)="setNumber(f.key, $event)" />
                    }
                    @default {
                      <input [id]="'wd-f-' + f.key" dir="auto" [readOnly]="readonly()" [value]="text(f)" [attr.data-field]="f.key"
                             [placeholder]="placeholderOf(f)" [attr.list]="f.kind === 'entity' ? 'wd-entities' : f.kind === 'workflow' ? 'wd-workflows' : null"
                             (change)="setConfig(f.key, valueOf($event).trim() || undefined)" />
                    }
                  }
                  @if (f.hint) { <p class="wd-muted">{{ f.hint }}</p> }
                </div>
              } @empty {
                <p class="wd-muted">{{ 'workflowDesigner.noSettings' | translate }}</p>
              }
            } @else {
              <p class="wd-muted">{{ 'workflowDesigner.pick' | translate }}</p>
            }
          </aside>
        </div>
        <datalist id="wd-entities">@for (e of entityNames(); track e) {<option [value]="e"></option>}</datalist>
        <datalist id="wd-workflows">@for (w of workflowNames(); track w) {<option [value]="w"></option>}</datalist>
      }
    </section>
  `,
  styles: [`
    .wd { display: grid; gap: .75rem; padding: 1rem; }
    .wd-head { display: flex; align-items: baseline; gap: .75rem; flex-wrap: wrap; }
    .wd-head h2 { margin: 0; font-size: 1.25rem; }
    .wd-classic { margin-inline-start: auto; }
    .wd-badge { font-size: .75rem; padding-inline: .5rem; border-radius: 999px; background: var(--color-bg-alt, #eef2f7); }
    .wd-body { display: grid; grid-template-columns: minmax(10rem, 13rem) minmax(0, 1fr) minmax(14rem, 18rem); gap: .75rem; align-items: start; }
    @media (max-width: 64rem) { .wd-body { grid-template-columns: minmax(0, 1fr); } }
    .wd-palette, .wd-settings { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; display: grid; gap: .5rem; }
    .wd-types { list-style: none; margin: 0; padding: 0; display: grid; gap: .25rem; max-block-size: 60vh; overflow: auto; }
    .wd-types button { inline-size: 100%; text-align: start; }
    .wd-settings h3 { margin: 0; font-size: 1rem; }
    .wd-field { display: grid; gap: .25rem; font-size: .8125rem; }
    .wd-json { font-family: ui-monospace, monospace; min-block-size: 5rem; }
    .wd-actions { display: flex; gap: .5rem; justify-content: flex-end; align-items: center; margin-block-start: .5rem; }
    .wd-muted { color: var(--color-text-secondary, #666); margin: 0; font-size: .8125rem; }
    .wd-error { color: var(--color-danger, #c53030); margin: 0; }
    .wd-label { font-size: .8125rem; }
  `],
})
export class WorkflowDesignerComponent implements OnInit {
  readonly definitionId = input.required<string>();
  readonly versionId = input.required<string>();

  private readonly svc = inject(WorkflowAdminService);
  private readonly admin = inject(AdminService);
  private readonly lang = inject(LangService);
  private readonly router = inject(Router);

  readonly kinds: GraphNodeKind[] = NODE_TYPES;
  private readonly canvas = viewChild(GraphCanvasComponent);

  readonly version = signal<VersionDetail | null>(null);
  readonly initial = signal<GraphDoc>({ nodes: [], edges: [] });
  readonly current = signal<GraphDoc>({ nodes: [], edges: [] });
  private readonly savedJson = signal('');
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly saveError = signal<string | null>(null);
  readonly busy = signal(false);
  readonly selected = signal<string | null>(null);
  readonly query = signal('');
  readonly jsonErrors = signal<Record<string, boolean>>({});
  readonly entityNames = signal<string[]>([]);
  readonly workflowNames = signal<string[]>([]);

  readonly readonly = computed(() => this.version()?.status !== 'draft');
  readonly dirty = computed(() => JSON.stringify(this.current()) !== this.savedJson());
  readonly palette = computed(() => paletteMatches(this.kinds, this.query(), t => this.typeLabel(t)));
  readonly selectedNode = computed(() => {
    const id = this.selected();
    const nodes = this.current().nodes;
    const index = nodes.findIndex(n => n.id === id);
    return index >= 0 ? { node: nodes[index], index } : null;
  });
  readonly fields = computed<NodeConfigField[]>(() => {
    const sel = this.selectedNode();
    return sel ? nodeConfigFields(sel.node.type) : [];
  });

  ngOnInit(): void {
    this.svc.getVersion(this.definitionId(), this.versionId()).subscribe({
      next: v => this.loaded(v),
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
    this.admin.listEntities().subscribe({
      next: es => this.entityNames.set(es.map(e => e.logicalname).sort()),
      error: () => { /* autocomplete only; free text still works */ },
    });
    this.svc.listDefinitions(true).subscribe({
      next: ds => this.workflowNames.set(ds.map(d => d.logicalname).sort()),
      error: () => { /* autocomplete only; free text still works */ },
    });
  }

  private loaded(v: VersionDetail): void {
    const doc = placedGraph(v.graph);
    this.version.set(v);
    this.initial.set(doc);
    this.current.set(doc);
    this.savedJson.set(JSON.stringify(doc));
    this.loading.set(false);
  }

  typeLabel(type: string): string {
    const k = `workflowNodeType.${type}`;
    const label = this.lang.translate(k);
    return label === k ? (nodeTypeSpec(type)?.label ?? type) : label;
  }

  /** Adds a node of `type` below the lowest one, selected. */
  add(type: string): void {
    const nodes = this.current().nodes;
    const y = nodes.length ? Math.max(...nodes.map(n => n.ports.y)) + 160 : 40;
    const x = nodes.length ? nodes[nodes.length - 1].ports.x : 40;
    const id = this.canvas()?.addNode(type, x, y);
    if (id) this.selected.set(id);
  }

  placeholderOf(f: NodeConfigField): string {
    return f.default === undefined ? '' : String(f.default);
  }

  configValue(f: NodeConfigField): unknown {
    return this.selectedNode()?.node.config?.[f.key];
  }

  text(f: NodeConfigField): string {
    const v = this.configValue(f);
    return v === undefined || v === null ? '' : String(v);
  }

  json(f: NodeConfigField): string {
    const v = this.configValue(f);
    return v === undefined ? '' : JSON.stringify(v, null, 2);
  }

  /** Sets (or, with `undefined`, clears) a setting of the selected node. */
  setConfig(key: string, value: unknown): void {
    const sel = this.selectedNode();
    const canvas = this.canvas();
    if (!sel || !canvas) return;
    const base = `/nodes/${sel.index}/config`;
    const path = `${base}/${key.replace(/~/g, '~0').replace(/\//g, '~1')}`;
    const config = sel.node.config;
    if (value === undefined) {
      if (config && key in config) canvas.exec({ op: 'remove', path });
      return;
    }
    if (!config || typeof config !== 'object') canvas.exec({ op: 'set', path: base, value: { [key]: value } });
    else canvas.exec({ op: 'set', path, value });
  }

  setNumber(key: string, event: Event): void {
    const raw = this.valueOf(event).trim();
    this.setConfig(key, raw === '' || Number.isNaN(Number(raw)) ? undefined : Number(raw));
  }

  setJson(key: string, event: Event): void {
    const raw = this.valueOf(event).trim();
    if (raw === '') {
      this.jsonErrors.update(e => ({ ...e, [key]: false }));
      this.setConfig(key, undefined);
      return;
    }
    try {
      const parsed: unknown = JSON.parse(raw);
      this.jsonErrors.update(e => ({ ...e, [key]: false }));
      this.setConfig(key, parsed);
    } catch {
      this.jsonErrors.update(e => ({ ...e, [key]: true }));
    }
  }

  save(): void {
    const v = this.version();
    if (!v || this.readonly()) return;
    const graph = this.current();
    this.busy.set(true);
    this.saveError.set(null);
    this.svc.updateVersionGraph(this.definitionId(), v.id, { graph, row_version: v.row_version }).subscribe({
      next: updated => {
        this.version.set(updated);
        this.savedJson.set(JSON.stringify(graph));
        this.busy.set(false);
      },
      error: (e: ApiError) => { this.saveError.set(e.message); this.busy.set(false); },
    });
  }

  publish(): void {
    const v = this.version();
    if (!v || this.dirty()) return;
    this.busy.set(true);
    this.saveError.set(null);
    this.svc.publishVersion(this.definitionId(), v.id).subscribe({
      next: updated => { this.version.set(updated); this.busy.set(false); },
      error: (e: ApiError) => { this.saveError.set(e.message); this.busy.set(false); },
    });
  }

  /** Opens the flow a sub-flow node runs: its draft, else its latest version. */
  openSubflow(node: GraphDocNode): void {
    const name = node.config?.['definition_logicalname'];
    if (typeof name !== 'string' || !name) {
      this.saveError.set(this.lang.translate('workflowDesigner.noSubflow'));
      return;
    }
    this.svc.listDefinitions().subscribe({
      next: ds => {
        const def = ds.find(d => d.logicalname === name);
        if (!def) { this.saveError.set(this.lang.translate('workflowDesigner.subflowMissing', { name })); return; }
        this.svc.getDefinition(def.id).subscribe({
          next: detail => {
            const versions = [...detail.versions].sort((a, b) => b.version_number - a.version_number);
            const target = versions.find(x => x.status === 'draft') ?? versions[0];
            if (!target) { this.saveError.set(this.lang.translate('workflowDesigner.subflowMissing', { name })); return; }
            void this.router.navigate(['/xrm/workflow/definitions', def.id, 'versions', target.id, 'design']);
          },
          error: (e: ApiError) => this.saveError.set(e.message),
        });
      },
      error: (e: ApiError) => this.saveError.set(e.message),
    });
  }

  protected valueOf(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected checked(event: Event): boolean {
    return (event.target as HTMLInputElement).checked;
  }
}
