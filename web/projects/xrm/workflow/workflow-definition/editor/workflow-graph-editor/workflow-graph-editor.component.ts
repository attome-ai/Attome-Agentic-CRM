import {
  ChangeDetectionStrategy, Component, ElementRef, HostListener, OnInit,
  computed, effect, inject, input, signal, viewChild,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';
import { AdminService } from '@attome/xrm/core/admin/data';
import { entityFormRoute } from '@attome/xrm/core/entity';

import {
  Graph, GraphEdge, GraphNode, NODE_TYPES, NodeConfigField, NodeTypeSpec, SimulateResponse,
  VersionDetail, WorkflowAdminService, nodeConfigFields, nodeTypeSpec,
} from '../../../services/workflow-admin.service';

/* ── Node-card geometry ─────────────────────────────────────────────────────
 * The edge layer has no access to laid-out DOM — it draws each wire straight
 * from the node's stored x/y — so these numbers must stay in lockstep with
 * workflow-graph-editor.css. Every one of them is a fixed value there
 * (`.node` width/border, `.node-header` height, `.port-col` padding/gap,
 * `.port` height, the dot's -6px offset), deliberately, so nothing about the
 * font stack or a wrapping label can move a port out from under its wire.
 */
const NODE_WIDTH  = 160;   // .node width, border-box
const NODE_BORDER = 1.5;   // .node border-width
const HEADER_H    = 32;    // .node-header height, border-box (includes its 1px bottom border)
const PORT_TOP    = 6;     // .port-col padding-top
const PORT_H      = 16;    // .port height
const PORT_GAP    = 4;     // .port-col gap
/** Distance from the node's outer left/right edge to the centre of a port dot:
 *  the dot straddles the border (`left: -6px` on a 10px dot whose containing
 *  box starts after the 1.5px border), so 1.5 - 6 + 5 = 0.5. */
const PORT_INSET  = 0.5;

/** Nodes stay clear of the canvas top so the `#n` badge above them, which
 *  hangs outside the node box, is never clipped by the scroll container. */
const MIN_Y = 24;

interface DragState { nodeId: string; offsetX: number; offsetY: number }

/** A canvas pan in progress: where the grab started, and the offset the
 *  surface had at that moment. */
interface PanState { startX: number; startY: number; originX: number; originY: number }

/**
 * A wire being dragged. `nodeId`/`port`/`isInput` is the *anchored* end (the
 * port the drag started from, or the far end of an edge being re-routed);
 * `x`/`y` is the free end following the cursor in canvas space.
 *
 * `detached` is the edge this wire was pulled off an input port — already
 * removed from the graph, so releasing anywhere but a valid port leaves it
 * deleted. Escape puts it back.
 */
interface PendingEdge {
  nodeId: string;
  port: string;
  isInput: boolean;
  x: number;
  y: number;
  detached?: GraphEdge;
}

/** The node-type picker, at canvas-space `x`/`y`. `source` is set when it was
 *  opened from an output port's `+`, which both narrows the list to types that
 *  can receive that port and wires the chosen node up on the way in. */
interface TypeMenu { x: number; y: number; source?: { nodeId: string; port: string } }

/**
 * Visual node-graph editor (P-workflow-engine.md §5 step 11 / phase 2).
 * Node types, ports, and port-type compatibility mirror
 * `attome_workflow::node_types` exactly (`NODE_TYPES` in workflow-admin.service.ts)
 * — the canvas is a client-side view over the same `graph` JSON the backend
 * validator (`attome_workflow::graph::validate`) checks at publish time, so a
 * client-side mistake still surfaces as a real, actionable publish error
 * rather than a silently-accepted bad graph.
 *
 * Node config is edited through a **per-type generated form** driven by
 * `NODE_CONFIG_SCHEMA` (workflow-admin.service.ts), which mirrors the keys
 * each executor in `attome_workflow::scheduler` actually reads — a Condition
 * gets field/op/value, a Webhook gets url/method, and neither shows the
 * other's keys. The schema is a UI affordance, not a validator: publish-time
 * validation is still the backend's (`attome_workflow::graph::validate`).
 *
 * There is deliberately no raw-JSON editor (removed on request — the whole
 * point of the generated form is not having to hand-write config). A config
 * key the schema does not describe is therefore not editable in this UI, but
 * it is never *destroyed*: `setConfig` spreads over the existing object, so
 * unknown keys survive every edit and save untouched, and the inspector
 * lists them so their presence is at least visible. If an executor gains a
 * key, add it to `NODE_CONFIG_SCHEMA` — node-config-schema.lockstep.spec.ts
 * fails until you do.
 *
 * A node is removed by selecting it and pressing Delete/Backspace; the
 * inspector carries no delete button.
 */
@Component({
  selector:   'attome-workflow-graph-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, RouterLink, TranslatePipe],
  host: {
    '(window:mousemove)': 'onWindowMouseMove($event)',
    '(window:mouseup)':   'onWindowMouseUp()',
  },
  styleUrls:  ['../../../../styles/admin-page.css', './workflow-graph-editor.component.css'],
  templateUrl: './workflow-graph-editor.component.html',
})
export class WorkflowGraphEditorComponent implements OnInit {
  private readonly svc   = inject(WorkflowAdminService);
  private readonly admin = inject(AdminService);

  readonly definitionId = input.required<string>();
  readonly versionId    = input.required<string>();

  // The bespoke definition editor page is gone — versions now live on the
  // generic entity form, so the breadcrumb goes there (with ?id=) instead.
  readonly workflowFormRoute = entityFormRoute('workflow_definition');

  readonly version  = signal<VersionDetail | null>(null);
  readonly graph     = signal<Graph>({ nodes: [], edges: [] });
  readonly loading   = signal(true);
  readonly error     = signal<string | null>(null);
  readonly saving    = signal(false);
  readonly saveError = signal<string | null>(null);
  readonly publishing = signal(false);
  readonly dirty     = signal(false);

  /** M06 checklist item 2 — dry-run over the version's currently *saved*
   *  graph (the backend reads it from `workflow_definition_version`,
   *  the same way `publish()` does) — disabled while `dirty()`, same as
   *  Publish above, so "Test" never silently exercises a graph shape the
   *  designer no longer shows. */
  readonly simulating   = signal(false);
  readonly simulateError = signal<string | null>(null);
  readonly simulateResult = signal<SimulateResponse | null>(null);

  readonly selectedNodeId = signal<string | null>(null);
  readonly pendingEdge    = signal<PendingEdge | null>(null);

  /** Datalist sources for the `entity` / `workflow` field kinds. Both are
   *  best-effort: the inputs they decorate are ordinary free text, so a
   *  failed load (e.g. a workflow author without admin-entity read) costs
   *  autocomplete, not the ability to configure the node. */
  readonly entityNames   = signal<string[]>([]);
  readonly workflowNames = signal<string[]>([]);

  /** `json`-kind fields edit text, not the parsed value — the buffer holds
   *  what is typed so a half-written object does not round-trip through
   *  JSON.stringify on every keystroke. Parsed into config on blur. */
  private readonly jsonText = signal<Record<string, string>>({});
  readonly jsonError        = signal<Record<string, string>>({});

  /** The node-type picker: opened by double-clicking the canvas (free-standing
   *  node at that point) or by the `+` beside an output port (`source` set,
   *  which both filters the list to compatible types and wires the result). */
  readonly typeMenu   = signal<TypeMenu | null>(null);
  readonly menuFilter = signal('');

  /** Canvas offset. The work surface is bigger than its frame and is moved by
   *  dragging its background instead of by scrollbars. Everything else keeps
   *  working in canvas space: `canvasOffset()` reads the transformed rect, so
   *  node drags, wires and the picker all land where the cursor is. */
  readonly panX = signal(0);
  readonly panY = signal(0);
  readonly panning = signal(false);

  private readonly canvasRef = viewChild<ElementRef<HTMLElement>>('canvas');
  private readonly canvasWrapRef = viewChild<ElementRef<HTMLElement>>('canvasWrap');
  private readonly menuSearchRef = viewChild<ElementRef<HTMLInputElement>>('menuSearch');

  private dragState: DragState | null = null;
  private panState: PanState | null = null;
  private savedGraphJson = '';
  /** Set by a port's own mouseup so the window-level handler, which fires
   *  afterwards on the way up, does not also treat that release as a drop on
   *  empty canvas. */
  private wireHandled = false;

  readonly readonly = computed(() => this.version()?.status !== 'draft');
  readonly selectedNode = computed(() =>
    this.graph().nodes.find(n => n.id === this.selectedNodeId()) ?? null,
  );

  /** Node types the open menu offers. With a `source` output port this is the
   *  set that can actually receive it, so the menu can only build an edge the
   *  publish validator accepts. */
  readonly menuOptions = computed<NodeTypeSpec[]>(() => {
    const menu = this.typeMenu();
    if (!menu) return [];
    const sourceType = menu.source
      ? this.portTypeOf(menu.source.nodeId, menu.source.port, false)
      : undefined;
    const q = this.menuFilter().trim().toLowerCase();
    return NODE_TYPES.filter(t => {
      if (menu.source && !t.inputs.some(p => this.portTypesCompatible(sourceType, p.portType))) return false;
      return q === '' || t.label.toLowerCase().includes(q) || t.type.includes(q);
    });
  });

  constructor() {
    // The picker is keyboard-first: whenever it opens, focus lands in its
    // filter box so a type can be narrowed down without reaching for the mouse.
    effect(() => this.menuSearchRef()?.nativeElement.focus());
  }

  ngOnInit(): void {
    this.svc.getVersion(this.definitionId(), this.versionId()).subscribe({
      next: v => {
        this.version.set(v);
        const g: Graph = v.graph && v.graph.nodes ? v.graph : { nodes: [], edges: [] };
        for (const n of g.nodes) { n.ports ??= { x: 40, y: 40 }; }
        this.graph.set(g);
        this.savedGraphJson = JSON.stringify(g);
        this.loading.set(false);
      },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });

    // Autocomplete sources for the entity/workflow config fields. Errors are
    // deliberately swallowed: these only populate a <datalist>, and the
    // inputs stay free text either way (see `entityNames` above).
    this.admin.listEntities().subscribe({
      next: es => this.entityNames.set(es.map(e => e.logicalname).sort()),
      error: () => { /* autocomplete unavailable — free-text entry still works */ },
    });
    this.svc.listDefinitions(true).subscribe({
      next: ds => this.workflowNames.set(ds.map(d => d.logicalname).sort()),
      error: () => { /* autocomplete unavailable — free-text entry still works */ },
    });
  }

  specOf(type: string): NodeTypeSpec | undefined { return nodeTypeSpec(type); }

  private markDirty(): void {
    this.dirty.set(JSON.stringify(this.graph()) !== this.savedGraphJson);
  }

  private mutate(fn: (g: Graph) => Graph): void {
    this.graph.update(fn);
    this.markDirty();
  }

  /** Adds a node at a canvas-space point and selects it. The graph keeps
   *  identifying nodes by `id` (that is what edges and publish errors use) —
   *  the number the canvas shows is only its position in this list. */
  addNode(type: string, x: number, y: number): string {
    const id = `${type}-${Math.random().toString(36).slice(2, 8)}`;
    const node: GraphNode = { id, type, config: {}, ports: { x: Math.max(0, x), y: Math.max(MIN_Y, y) } };
    this.mutate(g => ({ ...g, nodes: [...g.nodes, node] }));
    this.select(id);
    return id;
  }

  /** Toolbar/keyboard entry point: drops a node in the next free slot. */
  addNodeAt(type: string): void {
    if (this.readonly()) return;
    const count = this.graph().nodes.length;
    this.addNode(type, 60 + (count % 5) * 40, 60 + Math.floor(count / 5) * 140);
  }

  /** 1-based position of a node in the graph, shown as `#3` on the canvas in
   *  place of the generated id, which is noise while wiring. Deleting a node
   *  renumbers the ones after it — this is a label, not an identifier. */
  nodeNumber(nodeId: string): number {
    return this.graph().nodes.findIndex(n => n.id === nodeId) + 1;
  }

  select(nodeId: string): void {
    this.selectedNodeId.set(nodeId);
    this.jsonError.set({});
    this.reseedJsonBuffers();
  }

  // ── Node-type picker ──────────────────────────────────────────────────────

  /** Double-click on empty canvas: pick a type, get a node right there. A
   *  double-click that landed on a node is ignored — that is a node gesture. */
  openCanvasMenu(evt: MouseEvent): void {
    if (this.readonly()) return;
    if (evt.target !== this.canvasRef()?.nativeElement) return;
    const canvasRect = this.canvasOffset();
    this.menuFilter.set('');
    this.typeMenu.set({ x: evt.pageX - canvasRect.left, y: evt.pageY - canvasRect.top });
  }

  /** The `+` beside an output port of the selected node. */
  openOutputMenu(evt: Event, nodeId: string, port: string): void {
    evt.stopPropagation();
    if (this.readonly()) return;
    const pos = this.portScreenPos(nodeId, port, false);
    this.menuFilter.set('');
    this.typeMenu.set({ x: pos.x + 24, y: pos.y - 8, source: { nodeId, port } });
  }

  closeTypeMenu(): void {
    if (this.typeMenu()) this.typeMenu.set(null);
  }

  chooseType(type: string): void {
    const menu = this.typeMenu();
    this.closeTypeMenu();
    if (!menu || this.readonly()) return;
    if (!menu.source) { this.addNode(type, menu.x, menu.y); return; }
    this.addConnectedNode(type, menu.source.nodeId, menu.source.port);
  }

  /** Creates `type` to the right of the source node and wires the source
   *  output into the first input of the new node that accepts it — the menu
   *  only offered types for which such an input exists. */
  private addConnectedNode(type: string, fromNode: string, fromPort: string): void {
    const source = this.graph().nodes.find(n => n.id === fromNode);
    if (!source) return;
    const sourceType = this.portTypeOf(fromNode, fromPort, false);
    const target = nodeTypeSpec(type)?.inputs
      .find(p => this.portTypesCompatible(sourceType, p.portType));
    const spot = this.freeSpotRightOf(source);
    const id = this.addNode(type, spot.x, spot.y);
    if (!target) return;
    this.mutate(g => ({
      ...g,
      edges: [...g.edges, { from_node: fromNode, from_port: fromPort, to_node: id, to_port: target.name }],
    }));
  }

  /** A landing spot one node-width to the right, pushed down past anything
   *  already sitting there so a chain of `+` clicks does not stack up. */
  private freeSpotRightOf(source: GraphNode): { x: number; y: number } {
    const x = source.ports.x + NODE_WIDTH + 70;
    let y = source.ports.y;
    while (this.graph().nodes.some(n => Math.abs(n.ports.x - x) < NODE_WIDTH && Math.abs(n.ports.y - y) < 90)) {
      y += 130;
    }
    return { x, y };
  }

  // ── Generated per-type config form ────────────────────────────────────────

  /** Refills the `json`-kind text buffers from the newly-selected node. Only
   *  needed on selection: an ordinary field edit already owns its buffer. */
  private reseedJsonBuffers(): void {
    const n = this.selectedNode();
    const buffers: Record<string, string> = {};
    for (const f of nodeConfigFields(n?.type ?? '')) {
      if (f.kind !== 'json') continue;
      const v = n?.config?.[f.key];
      buffers[f.key] = v === undefined ? '' : JSON.stringify(v, null, 2);
    }
    this.jsonText.set(buffers);
  }

  /** Schema fields for the selected node, minus those whose `showIf` gate is
   *  not currently satisfied (e.g. Condition's "Compare to" under `truthy`). */
  readonly visibleConfigFields = computed<NodeConfigField[]>(() => {
    const n = this.selectedNode();
    if (!n) return [];
    const fields = nodeConfigFields(n.type);
    return fields.filter(f => {
      if (!f.showIf) return true;
      const gate = fields.find(g => g.key === f.showIf!.key);
      const current = n.config?.[f.showIf.key] ?? gate?.default;
      return f.showIf.in.includes(String(current));
    });
  });

  /** Config keys the schema does not describe — never dropped, only flagged,
   *  so a key an executor gained before this schema did stays editable. */
  readonly extraConfigKeys = computed<string[]>(() => {
    const n = this.selectedNode();
    if (!n?.config) return [];
    const known = new Set(nodeConfigFields(n.type).map(f => f.key));
    return Object.keys(n.config).filter(k => !known.has(k));
  });

  private rawValue(key: string): unknown {
    return this.selectedNode()?.config?.[key];
  }

  /** Text/select display value: the stored value, else the executor default
   *  for a select (so the dropdown shows what will actually run), else ''. */
  stringValue(f: NodeConfigField): string {
    const v = this.rawValue(f.key);
    if (v !== undefined && v !== null) return String(v);
    return f.kind === 'select' && f.default !== undefined ? String(f.default) : '';
  }

  numberValue(f: NodeConfigField): number | null {
    const v = this.rawValue(f.key);
    return typeof v === 'number' ? v : null;
  }

  boolValue(f: NodeConfigField): boolean {
    return this.rawValue(f.key) === true;
  }

  /** Placeholder shows the executor's fallback, making "left blank" legible
   *  as "uses 72", not as "unset and maybe broken". */
  placeholderFor(f: NodeConfigField): string {
    return f.default === undefined || f.default === false ? '' : String(f.default);
  }

  datalistFor(f: NodeConfigField): string | null {
    if (f.kind === 'entity')   return 'wf-entity-names';
    if (f.kind === 'workflow') return 'wf-workflow-names';
    return null;
  }

  isMissingRequired(f: NodeConfigField): boolean {
    return f.required === true && this.stringValue(f).trim() === '';
  }

  /** Writes one config key. `undefined` deletes it, so clearing a field falls
   *  back to the executor default instead of persisting an empty string. */
  setConfig(key: string, value: unknown): void {
    const id = this.selectedNodeId();
    if (!id || this.readonly()) return;
    this.mutate(g => ({
      ...g,
      nodes: g.nodes.map(n => {
        if (n.id !== id) return n;
        const config = { ...n.config };
        if (value === undefined) { delete config[key]; } else { config[key] = value; }
        return { ...n, config };
      }),
    }));
  }

  jsonBuffer(key: string): string { return this.jsonText()[key] ?? ''; }

  setJsonBuffer(key: string, text: string): void {
    this.jsonText.update(b => ({ ...b, [key]: text }));
  }

  applyJsonField(key: string): void {
    const text = this.jsonBuffer(key).trim();
    if (text === '') {
      this.jsonError.update(e => ({ ...e, [key]: '' }));
      this.setConfig(key, undefined);
      return;
    }
    try {
      const parsed: unknown = JSON.parse(text);
      this.jsonError.update(e => ({ ...e, [key]: '' }));
      this.setConfig(key, parsed);
    } catch {
      this.jsonError.update(e => ({ ...e, [key]: 'must be valid JSON' }));
    }
  }

  /**
   * Delete/Backspace removes the selected node — the inspector no longer
   * carries a Delete button. Ignored while a text control has focus (typing
   * a config value must not eat the node) and on read-only versions.
   */
  @HostListener('window:keydown', ['$event'])
  onWindowKeyDown(evt: KeyboardEvent): void {
    // Escape backs out of whatever is open: the type picker first, then a wire
    // in flight. Unlike dropping a wire on empty canvas, Escape puts a detached
    // edge back — it means "never mind", not "delete".
    if (evt.key === 'Escape' && (this.typeMenu() || this.pendingEdge())) {
      evt.preventDefault();
      if (this.typeMenu()) { this.closeTypeMenu(); return; }
      this.cancelWire(true);
      return;
    }
    if (evt.key !== 'Delete' && evt.key !== 'Backspace') return;
    if (evt.ctrlKey || evt.metaKey || evt.altKey) return;
    if (this.readonly()) return;
    if (this.isTextEntryTarget(evt.target)) return;
    const id = this.selectedNodeId();
    if (!id) return;
    evt.preventDefault();
    this.deleteNode(id);
  }

  private isTextEntryTarget(target: EventTarget | null): boolean {
    const el = target as HTMLElement | null;
    if (!el || typeof el.tagName !== 'string') return false;
    if (el.isContentEditable) return true;
    return ['INPUT', 'TEXTAREA', 'SELECT'].includes(el.tagName);
  }

  deleteNode(nodeId: string): void {
    if (this.readonly()) return;
    this.mutate(g => ({
      nodes: g.nodes.filter(n => n.id !== nodeId),
      edges: g.edges.filter(e => e.from_node !== nodeId && e.to_node !== nodeId),
    }));
    if (this.selectedNodeId() === nodeId) {
      this.selectedNodeId.set(null);
      this.jsonText.set({});
      this.jsonError.set({});
    }
  }

  edgeKey(e: GraphEdge): string { return `${e.from_node}:${e.from_port}->${e.to_node}:${e.to_port}`; }

  removeEdge(index: number): void {
    this.mutate(g => ({ ...g, edges: g.edges.filter((_, i) => i !== index) }));
  }

  // ── Dragging ──────────────────────────────────────────────────────────────

  startDrag(evt: MouseEvent, node: GraphNode): void {
    if (this.readonly()) return;
    // Grab offset measured from the node's own origin, not `evt.offsetX`:
    // that is relative to whichever child was hit (header, id row, port row),
    // so the node jumped under the cursor on every drag that did not start in
    // the node's top-left corner.
    const canvasRect = this.canvasOffset();
    this.dragState = {
      nodeId:  node.id,
      offsetX: evt.pageX - canvasRect.left - node.ports.x,
      offsetY: evt.pageY - canvasRect.top - node.ports.y,
    };
  }

  // ── Panning ───────────────────────────────────────────────────────────────

  /** Mouse down on the canvas background — that is, not on a node, a port or
   *  the picker, all of which stop the event — starts a pan. */
  onCanvasMouseDown(evt: MouseEvent): void {
    this.closeTypeMenu();
    if (evt.button !== 0) return;
    if (evt.target !== this.canvasRef()?.nativeElement) return;
    evt.preventDefault();   // no text selection while dragging the surface
    this.panState = { startX: evt.pageX, startY: evt.pageY, originX: this.panX(), originY: this.panY() };
    this.panning.set(true);
  }

  /** Wheel scrolls the surface rather than the page (shift for horizontal),
   *  so the trackpad still works without a scroll track being present. */
  onCanvasWheel(evt: WheelEvent): void {
    evt.preventDefault();
    const [dx, dy] = evt.shiftKey && evt.deltaX === 0
      ? [-evt.deltaY, 0]
      : [-evt.deltaX, -evt.deltaY];
    this.setPan(this.panX() + dx, this.panY() + dy);
  }

  /** Clamped so the surface always covers the frame: the graph can never be
   *  pushed off into empty space where a node would be unreachable. */
  private setPan(x: number, y: number): void {
    const surface = this.canvasRef()?.nativeElement;
    const frame   = this.canvasWrapRef()?.nativeElement;
    const minX = Math.min(0, (frame?.clientWidth  ?? 0) - (surface?.offsetWidth  ?? 0));
    const minY = Math.min(0, (frame?.clientHeight ?? 0) - (surface?.offsetHeight ?? 0));
    this.panX.set(Math.min(0, Math.max(minX, x)));
    this.panY.set(Math.min(0, Math.max(minY, y)));
  }

  onWindowMouseMove(evt: MouseEvent): void {
    if (this.panState) {
      this.setPan(
        this.panState.originX + (evt.pageX - this.panState.startX),
        this.panState.originY + (evt.pageY - this.panState.startY),
      );
      return;
    }
    if (this.dragState) {
      const { nodeId } = this.dragState;
      const canvasRect = this.canvasOffset();
      const x = evt.pageX - canvasRect.left - this.dragState.offsetX;
      const y = evt.pageY - canvasRect.top - this.dragState.offsetY;
      this.graph.update(g => ({
        ...g,
        nodes: g.nodes.map(n => (n.id === nodeId ? { ...n, ports: { x: Math.max(0, x), y: Math.max(MIN_Y, y) } } : n)),
      }));
      return;
    }
    const p = this.pendingEdge();
    if (p) {
      const canvasRect = this.canvasOffset();
      this.pendingEdge.set({ ...p, x: evt.pageX - canvasRect.left, y: evt.pageY - canvasRect.top });
    }
  }

  onWindowMouseUp(): void {
    if (this.panState) { this.panState = null; this.panning.set(false); }
    if (this.dragState) { this.dragState = null; this.markDirty(); }
    // A port's own mouseup already resolved this release (bubbling reaches the
    // port first, then the window) — do not undo its decision.
    if (this.wireHandled) { this.wireHandled = false; return; }
    // Released over anything that is not a port: the wire is dropped. A wire
    // detached from an input stays detached, which is how an edge is deleted
    // by dragging its end off into empty canvas.
    this.cancelWire(false);
  }

  private canvasOffset(): { left: number; top: number } {
    const rect = this.canvasRef()?.nativeElement.getBoundingClientRect();
    return { left: (rect?.left ?? 0) + window.scrollX, top: (rect?.top ?? 0) + window.scrollY };
  }

  // ── Wiring ────────────────────────────────────────────────────────────────
  //
  // A port is both a drag handle and a drop target:
  //
  //   mousedown on an output port          → start a new wire from it
  //   mousedown on a wired input port      → detach that edge (removed now)
  //                                          and re-route its free end
  //   mousedown on an unwired input port   → start a wire backwards from it
  //   mouseup on the opposite kind of port → connect the two
  //   mouseup anywhere else                → drop the wire (a detached edge
  //                                          stays deleted)
  //
  // Press-and-release on the same port is a click, not a drag, so the wire is
  // left armed: click-output-then-click-input still wires an edge, which is
  // also what the keyboard path (`onPortActivate`) does.

  onPortMouseDown(evt: MouseEvent, nodeId: string, port: string, isInput: boolean): void {
    evt.stopPropagation();  // a port drag must never drag the node
    evt.preventDefault();   // ...nor select the node's text while wiring
    if (this.readonly()) return;
    if (this.pendingEdge()) return; // wire already in flight; mouseup resolves it
    this.beginWire(nodeId, port, isInput);
  }

  onPortMouseUp(evt: MouseEvent, nodeId: string, port: string, isInput: boolean): void {
    evt.stopPropagation();
    if (this.readonly()) return;
    const pending = this.pendingEdge();
    if (!pending) return;
    this.wireHandled = true;
    // Released on the very end we grabbed — treat as a click and stay armed.
    if (pending.nodeId === nodeId && pending.port === port && pending.isInput === isInput) return;
    this.completeWire(nodeId, port, isInput);
  }

  /** Keyboard equivalent of a port press: arms a wire, or lands the armed one. */
  onPortActivate(nodeId: string, port: string, isInput: boolean): void {
    if (this.readonly()) return;
    if (this.pendingEdge()) { this.completeWire(nodeId, port, isInput); return; }
    this.beginWire(nodeId, port, isInput);
  }

  private beginWire(nodeId: string, port: string, isInput: boolean): void {
    if (isInput) {
      const idx = this.edgeIndexInto(nodeId, port);
      if (idx >= 0) {
        const existing = this.graph().edges[idx];
        const pos = this.portScreenPos(nodeId, port, true);
        this.removeEdge(idx);
        this.pendingEdge.set({
          nodeId: existing.from_node, port: existing.from_port, isInput: false,
          x: pos.x, y: pos.y, detached: existing,
        });
        return;
      }
    }
    const pos = this.portScreenPos(nodeId, port, isInput);
    this.pendingEdge.set({ nodeId, port, isInput, x: pos.x, y: pos.y });
  }

  private completeWire(nodeId: string, port: string, isInput: boolean): void {
    const pending = this.pendingEdge();
    this.pendingEdge.set(null);
    if (!pending) return;
    if (!this.canConnect(pending, nodeId, port, isInput)) {
      this.restoreDetached(pending);   // illegal landing — undo a detach, if any
      return;
    }
    const edge = this.edgeBetween(pending, nodeId, port);
    // `edges` is tracked by `edgeKey` in the template, so a duplicate would be
    // a duplicate track key — and re-wiring a port to where it already went is
    // a no-op anyway.
    const key = this.edgeKey(edge);
    if (this.graph().edges.some(e => this.edgeKey(e) === key)) return;
    this.mutate(g => ({ ...g, edges: [...g.edges, edge] }));
  }

  /** Orients the wire: whichever end is the output becomes `from`. */
  private edgeBetween(pending: PendingEdge, nodeId: string, port: string): GraphEdge {
    return pending.isInput
      ? { from_node: nodeId, from_port: port, to_node: pending.nodeId, to_port: pending.port }
      : { from_node: pending.nodeId, from_port: pending.port, to_node: nodeId, to_port: port };
  }

  private canConnect(pending: PendingEdge, nodeId: string, port: string, isInput: boolean): boolean {
    if (pending.isInput === isInput) return false;   // two inputs, or two outputs
    if (pending.nodeId === nodeId) return false;     // no self-loops
    const edge = this.edgeBetween(pending, nodeId, port);
    return this.portTypesCompatible(
      this.portTypeOf(edge.from_node, edge.from_port, false),
      this.portTypeOf(edge.to_node, edge.to_port, true),
    );
  }

  private portTypeOf(nodeId: string, port: string, isInput: boolean): string | undefined {
    const node = this.graph().nodes.find(n => n.id === nodeId);
    const spec = this.specOf(node?.type ?? '');
    const list = isInput ? spec?.inputs ?? [] : spec?.outputs ?? [];
    return list.find(p => p.name === port)?.portType;
  }

  /** Mirrors `PortType::compatible_with` in `attome_workflow::node_types`: `any`
   *  goes with anything, otherwise the two types must match. Enforcing it on
   *  the canvas turns what would be a publish-time rejection into a drop the
   *  editor simply declines. An unknown port type (a node type this build does
   *  not know) is left to the backend rather than blocked here. */
  private portTypesCompatible(from: string | undefined, to: string | undefined): boolean {
    if (from === undefined || to === undefined) return true;
    return from === 'any' || to === 'any' || from === to;
  }

  /** Drops the wire in flight. `restore` puts a detached edge back (Escape);
   *  without it the detach stands, which is the drop-outside delete. */
  private cancelWire(restore: boolean): void {
    const pending = this.pendingEdge();
    if (!pending) return;
    this.pendingEdge.set(null);
    if (restore) this.restoreDetached(pending);
  }

  private restoreDetached(pending: PendingEdge): void {
    const e = pending.detached;
    if (!e) return;
    const key = this.edgeKey(e);
    if (this.graph().edges.some(x => this.edgeKey(x) === key)) return;
    this.mutate(g => ({ ...g, edges: [...g.edges, e] }));
  }

  /** Index of the edge terminating at this input port, newest first, or -1.
   *  Fan-in is legal, so grabbing the port re-routes the most recent wire. */
  private edgeIndexInto(nodeId: string, port: string): number {
    return this.graph().edges
      .map((e, i) => (e.to_node === nodeId && e.to_port === port ? i : -1))
      .reduce((last, i) => (i >= 0 ? i : last), -1);
  }

  isWired(nodeId: string, port: string, isInput: boolean): boolean {
    return this.graph().edges.some(e => (isInput
      ? e.to_node === nodeId && e.to_port === port
      : e.from_node === nodeId && e.from_port === port));
  }

  /** A port the wire in flight could legally land on — highlighted while dragging. */
  isDropTarget(nodeId: string, port: string, isInput: boolean): boolean {
    const pending = this.pendingEdge();
    return !!pending && this.canConnect(pending, nodeId, port, isInput);
  }

  /** The end the wire in flight is anchored to — kept lit while the rest of
   *  the unusable ports dim, so it stays obvious where the wire came from. */
  isWireAnchor(nodeId: string, port: string, isInput: boolean): boolean {
    const p = this.pendingEdge();
    return !!p && p.nodeId === nodeId && p.port === port && p.isInput === isInput;
  }

  /** Canvas-space (not screen-space) centre of a named port's dot. */
  portScreenPos(nodeId: string, port: string, isInput: boolean): { x: number; y: number } {
    const node = this.graph().nodes.find(n => n.id === nodeId);
    if (!node) return { x: 0, y: 0 };
    const spec = this.specOf(node.type);
    const list = isInput ? spec?.inputs ?? [] : spec?.outputs ?? [];
    const idx = Math.max(0, list.findIndex(p => p.name === port));
    const y = node.ports.y + NODE_BORDER + HEADER_H + PORT_TOP
            + idx * (PORT_H + PORT_GAP) + PORT_H / 2;
    const x = node.ports.x + (isInput ? PORT_INSET : NODE_WIDTH - PORT_INSET);
    return { x, y };
  }

  /** The `d` of a wire: a cubic bezier that leaves the output horizontally and
   *  arrives at the input horizontally, ComfyUI-style. The control arm grows
   *  with the gap so a short hop stays a gentle S rather than a hairpin, and a
   *  backwards edge (target left of source) gets extra reach so it bows out
   *  around the nodes instead of doubling back through them. */
  private wirePath(x1: number, y1: number, x2: number, y2: number): string {
    const dx = x2 - x1;
    const arm = Math.min(140, Math.max(40, Math.abs(dx) * 0.5))
              + Math.max(0, -dx) * 0.35;
    return `M ${x1} ${y1} C ${x1 + arm} ${y1}, ${x2 - arm} ${y2}, ${x2} ${y2}`;
  }

  /** A wired edge, drawn output → input. */
  edgePath(e: GraphEdge): string {
    const from = this.portScreenPos(e.from_node, e.from_port, false);
    const to   = this.portScreenPos(e.to_node, e.to_port, true);
    return this.wirePath(from.x, from.y, to.x, to.y);
  }

  /** The wire in flight. Drawn in the same output → input direction as a real
   *  edge, so a wire dragged backwards off an input curves the way it will
   *  once it lands rather than flipping when it does. */
  pendingPath(p: PendingEdge): string {
    const anchor = this.portScreenPos(p.nodeId, p.port, p.isInput);
    return p.isInput
      ? this.wirePath(p.x, p.y, anchor.x, anchor.y)
      : this.wirePath(anchor.x, anchor.y, p.x, p.y);
  }

  // ── Save / publish ───────────────────────────────────────────────────────

  save(): void {
    const v = this.version();
    if (!v) return;
    this.saving.set(true);
    this.saveError.set(null);
    this.svc.updateVersionGraph(this.definitionId(), v.id, { graph: this.graph(), row_version: v.row_version })
      .subscribe({
        next: updated => {
          this.version.set(updated);
          this.savedGraphJson = JSON.stringify(this.graph());
          this.dirty.set(false);
          this.saving.set(false);
        },
        error: (e: ApiError) => { this.saveError.set(e.message); this.saving.set(false); },
      });
  }

  publish(): void {
    const v = this.version();
    if (!v) return;
    this.publishing.set(true);
    this.saveError.set(null);
    this.svc.publishVersion(this.definitionId(), v.id).subscribe({
      next: updated => { this.version.set(updated); this.publishing.set(false); },
      error: (e: ApiError) => { this.saveError.set(e.message); this.publishing.set(false); },
    });
  }

  // ── Simulate / dry-run (M06 checklist item 2) ────────────────────────────

  simulate(): void {
    const v = this.version();
    if (!v) return;
    this.simulating.set(true);
    this.simulateError.set(null);
    this.simulateResult.set(null);
    this.svc.simulateVersion(this.definitionId(), v.id, { trigger_payload: {} }).subscribe({
      next: result => { this.simulateResult.set(result); this.simulating.set(false); },
      error: (e: ApiError) => { this.simulateError.set(e.message); this.simulating.set(false); },
    });
  }

  closeSimulateResult(): void {
    this.simulateResult.set(null);
  }
}
