import {
  ChangeDetectionStrategy, Component, TemplateRef, computed, effect, input, output, signal, untracked,
} from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { TranslatePipe } from '@attome/base';

import { CommandStack } from './command-stack';
import { EditCommand } from './commands';
import {
  CARD, GraphDoc, GraphDocEdge, GraphDocNode, GraphNodeKind, GraphNodeMark, PortRef, Refusal,
  cardHeight, checkConnection, connectCommand, edgeKey, ensureLists, freshId, groupBox, moveNodeCommand,
  outputsOf, portPoint, removeNodeCommands, wirePath,
} from './graph';

interface Drag { id: string; index: number; startX: number; startY: number; dx: number; dy: number }
interface Pending { from: PortRef; x: number; y: number }

/**
 * M2-T1 — the canvas in graph mode. Nodes sit where the builder puts them;
 * each shows its typed input ports on its start edge and its outputs (with
 * the error port) on its end edge. Dragging from an output to an input makes
 * an edge only when `checkConnection` allows it; while dragging, every input
 * shows whether it accepts the connection, and a refused drop says why (the
 * reason is also announced). The same works by clicking an output, then an
 * input, so the keyboard can connect too.
 *
 * - Drag a card's header to move it (kept on an 8-unit grid); arrows move
 *   the selected node, Alt with an arrow moves it further.
 * - Click a wire to select it; Delete removes the selected wire or node (a
 *   node goes with its wires).
 * - Ctrl or Cmd adds nodes to the selection; "Group" frames them with a
 *   label; "Note" adds a note.
 * - A node whose type is in `subflowTypes` has an open button
 *   (`openSubflow`).
 * - Ctrl+Z undoes, Ctrl+Y or Ctrl+Shift+Z redoes; Escape drops a pending
 *   connection and the selection.
 *
 * Every change is an edit command on the shared `CommandStack`, so undo and
 * redo are unlimited and `save` hands over the commands since the last save.
 * In Arabic the whole diagram mirrors: inputs on the right, flow to the left.
 *
 * The designer around it can mark nodes (`nodeMarks`: a problem, a simulated
 * run's result, a coverage gap, each with its note) and light edges
 * (`litEdges`). A state model's canvas (M8-T4) passes `allowCycles`, and
 * `edgesOnly` when the nodes are not the builder's to add or remove.
 */
@Component({
  selector: 'xrm-graph-canvas',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [NgTemplateOutlet, TranslatePipe],
  template: `
    <div class="gc">
      <div class="gc-toolbar" role="toolbar" [attr.aria-label]="'canvas.toolbar' | translate">
        <button type="button" data-testid="graph-undo" [disabled]="!stack().canUndo()" (click)="undo()">{{ 'canvas.undo' | translate }}</button>
        <button type="button" data-testid="graph-redo" [disabled]="!stack().canRedo()" (click)="redo()">{{ 'canvas.redo' | translate }}</button>
        @if (!readonly() && !edgesOnly()) {
          <button type="button" data-testid="graph-group" [disabled]="selectedNodes().length === 0" (click)="groupSelection()">{{ 'graphCanvas.group' | translate }}</button>
          <button type="button" data-testid="graph-note" (click)="addNote()">{{ 'graphCanvas.note' | translate }}</button>
          <button type="button" data-testid="graph-save" [disabled]="!stack().dirty()" (click)="emitSave()">{{ 'canvas.save' | translate }}</button>
        }
      </div>
      <p class="gc-status" role="status" aria-live="polite" data-testid="graph-status">
        @if (refusal(); as r) { {{ r.key | translate: r.params }} }
        @else if (pending()) { {{ 'graphCanvas.connecting' | translate }} }
      </p>
      <div class="gc-scroll" tabindex="0" data-testid="graph-surface" [attr.aria-label]="'graphCanvas.surface' | translate"
           (pointermove)="onPointerMove($event)" (pointerup)="onPointerUp()" (click)="onBackground($event)"
           (keydown)="onKey($event)">
        <div class="gc-plane" [style.inline-size.px]="extent().width" [style.block-size.px]="extent().height">
          @for (g of groupBoxes(); track g.group.id) {
            <div class="gc-group" data-testid="graph-group-frame" [class.gc-group--selected]="selectedGroup() === g.group.id"
                 [style.inset-inline-start.px]="g.box.x" [style.inset-block-start.px]="g.box.y"
                 [style.inline-size.px]="g.box.width" [style.block-size.px]="g.box.height">
              <button type="button" class="gc-group-label" dir="auto" (click)="selectGroup(g.group.id, $event)">{{ g.group.label }}</button>
            </div>
          }
          <svg class="gc-wires" [attr.width]="extent().width" [attr.height]="extent().height" aria-hidden="true">
            @for (w of wires(); track w.key) {
              <path class="gc-wire" [class.gc-wire--selected]="selectedEdge() === w.index"
                    [class.gc-wire--lit]="litEdges().includes(w.key)" [attr.d]="w.d"
                    data-testid="graph-wire" (click)="selectEdge(w.index, $event)" />
            }
            @if (pendingWire(); as d) { <path class="gc-wire gc-wire--pending" [attr.d]="d" /> }
          </svg>
          @for (n of cards(); track n.node.id) {
            <div class="gc-card" data-testid="graph-node" [attr.data-node]="n.node.id"
                 [class.gc-card--selected]="selectedNodes().includes(n.node.id)"
                 [attr.data-marks]="tonesOf(n.node.id)"
                 [style.inset-inline-start.px]="n.x" [style.inset-block-start.px]="n.y"
                 [style.inline-size.px]="cardWidth" [style.block-size.px]="n.height"
                 tabindex="0" [attr.aria-label]="cardLabel(n.kind?.label ?? n.node.type, n.node.id)"
                 (click)="selectNode(n.node.id, $event)" (keydown.enter)="selectNode(n.node.id)">
              <div class="gc-card-head" (pointerdown)="startDrag($event, n.node.id)">
                <span class="gc-type">{{ n.kind?.label ?? n.node.type }}</span>
                @if (nodeTemplate(); as tpl) {
                  <ng-container [ngTemplateOutlet]="tpl" [ngTemplateOutletContext]="{ $implicit: n.node }" />
                } @else if (n.node.id !== n.kind?.label) {
                  <bdi class="gc-id" dir="ltr">{{ n.node.id }}</bdi>
                }
                @for (m of marksOf(n.node.id); track m.tone) {
                  <span [class]="'gc-mark gc-mark--' + m.tone" data-testid="graph-mark"
                        [attr.data-tone]="m.tone" [title]="m.note" aria-hidden="true">{{ symbol(m.tone) }}</span>
                }
                @if (subflowTypes().includes(n.node.type)) {
                  <button type="button" class="gc-open" data-testid="graph-open-subflow"
                          [attr.aria-label]="'graphCanvas.openSubflow' | translate"
                          (click)="openSub(n.node, $event)">↗</button>
                }
              </div>
              <div class="gc-ports">
                <ul class="gc-in">
                  @for (p of n.kind?.inputs ?? []; track p.name) {
                    <li>
                      <button type="button" class="gc-port gc-port--in" data-testid="graph-port-in"
                              [attr.data-port]="p.name" [disabled]="readonly()"
                              [class.gc-port--ok]="pending() && accepts(n.node.id, p.name)"
                              [class.gc-port--no]="pending() && !accepts(n.node.id, p.name)"
                              [attr.aria-label]="('graphCanvas.input' | translate: { port: p.name, type: p.portType })"
                              (pointerenter)="hoverInput(n.node.id, p.name)" (pointerleave)="refusal.set(null)"
                              (pointerup)="finishAt(n.node.id, p.name, $event)" (click)="finishAt(n.node.id, p.name, $event)">
                        <span class="gc-dot" aria-hidden="true"></span>{{ p.name }}@if (p.required) {<span aria-hidden="true">*</span>}
                        <span class="gc-ptype">{{ p.portType }}</span>
                      </button>
                    </li>
                  }
                </ul>
                <ul class="gc-out">
                  @for (p of outputs(n.kind); track p.name) {
                    <li>
                      <button type="button" class="gc-port gc-port--out" data-testid="graph-port-out"
                              [attr.data-port]="p.name" [disabled]="readonly()"
                              [class.gc-port--armed]="isArmed(n.node.id, p.name)"
                              [attr.aria-label]="('graphCanvas.output' | translate: { port: p.name, type: p.portType })"
                              (pointerdown)="arm(n.node.id, p.name, $event)" (click)="toggleArm(n.node.id, p.name, $event)">
                        <span class="gc-ptype">{{ p.portType }}</span>{{ p.name }}<span class="gc-dot" aria-hidden="true"></span>
                      </button>
                    </li>
                  }
                </ul>
              </div>
            </div>
          }
          @for (note of notes(); track note.id; let i = $index) {
            <textarea class="gc-note" data-testid="graph-note-text" dir="auto" [readOnly]="readonly()"
                      [attr.aria-label]="'graphCanvas.noteLabel' | translate"
                      [style.inset-inline-start.px]="note.x" [style.inset-block-start.px]="note.y"
                      [value]="note.text" (click)="$event.stopPropagation()"
                      (change)="setNote(i, $event)"></textarea>
          }
        </div>
      </div>
      @if (selectedGroup(); as gid) {
        @if (groupIndex(gid); as gi) {
          <div class="gc-group-edit">
            <label [attr.for]="'gc-group-' + gid">{{ 'graphCanvas.groupLabel' | translate }}</label>
            <input [id]="'gc-group-' + gid" dir="auto" data-testid="graph-group-label" [value]="groupLabel(gi - 1)"
                   [readOnly]="readonly()" (change)="renameGroup(gi - 1, $event)" />
            @if (!readonly()) {
              <button type="button" (click)="ungroup(gi - 1)">{{ 'graphCanvas.ungroup' | translate }}</button>
            }
          </div>
        }
      }
    </div>
  `,
  styles: [`
    .gc { display: grid; gap: .5rem; }
    .gc-toolbar { display: flex; gap: .5rem; flex-wrap: wrap; }
    .gc-status { min-block-size: 1.25rem; margin: 0; font-size: .8125rem; color: var(--color-text-secondary, #555); }
    .gc-scroll { overflow: auto; border: 1px solid var(--color-border, #ddd); border-radius: 8px; max-block-size: 70vh;
                 background: var(--color-bg-alt, #fafbfc); }
    .gc-scroll:focus-visible { outline: 2px solid var(--color-primary, #2b6cb0); }
    .gc-plane { position: relative; }
    .gc-wires { position: absolute; inset-block-start: 0; inset-inline-start: 0; overflow: visible; }
    :host-context([dir=rtl]) .gc-wires { transform: scaleX(-1); }
    .gc-wire { fill: none; stroke: var(--color-text-secondary, #888); stroke-width: 2; cursor: pointer; pointer-events: stroke; }
    .gc-wire--selected { stroke: var(--color-primary, #2b6cb0); stroke-width: 3; }
    .gc-wire--lit { stroke: var(--color-success, #2f855a); stroke-width: 3; }
    .gc-wire--pending { stroke-dasharray: 6 4; pointer-events: none; }
    .gc-card { position: absolute; box-sizing: border-box; border: 1px solid var(--color-border, #ccc); border-radius: 8px;
               background: var(--color-bg, #fff); box-shadow: 0 1px 2px color-mix(in srgb, var(--color-text-secondary, transparent) 15%, transparent); }
    .gc-card--selected { border-color: var(--color-primary, #2b6cb0); box-shadow: 0 0 0 2px var(--color-primary-bg, #dbe8f7); }
    .gc-card[data-marks~="problem"], .gc-card[data-marks~="failed"] { border-color: var(--color-danger, #c53030); border-width: 2px; }
    .gc-card[data-marks~="ran"] { border-color: var(--color-success, #2f855a); border-width: 2px; }
    .gc-card[data-marks~="active"] { border-color: var(--color-warning, #b7791f); border-width: 2px; }
    .gc-card[data-marks~="initial"] { border-color: var(--color-primary, #2b6cb0); border-width: 2px; }
    .gc-card[data-marks~="skipped"] { opacity: .55; }
    .gc-card[data-marks~="uncovered"] { background: repeating-linear-gradient(45deg, var(--color-bg, #fff), var(--color-bg, #fff) 6px,
                                        var(--color-warning-bg, #fdf3d7) 6px, var(--color-warning-bg, #fdf3d7) 12px); }
    .gc-mark { font-size: .75rem; font-weight: 700; inline-size: 1rem; text-align: center; flex: none; }
    .gc-mark--problem, .gc-mark--failed { color: var(--color-danger, #c53030); }
    .gc-mark--ran { color: var(--color-success, #2f855a); }
    .gc-mark--uncovered, .gc-mark--skipped { color: var(--color-text-secondary, #666); }
    .gc-mark--active { color: var(--color-warning, #b7791f); }
    .gc-mark--initial { color: var(--color-primary, #2b6cb0); }
    .gc-card-head { display: flex; align-items: center; gap: .375rem; block-size: 32px; padding-inline: .5rem;
                    border-block-end: 1px solid var(--color-border, #eee); cursor: grab; touch-action: none; }
    .gc-type { font-weight: 600; font-size: .8125rem; }
    .gc-id { font-family: ui-monospace, monospace; font-size: .7rem; color: var(--color-text-secondary, #777);
             overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .gc-open { margin-inline-start: auto; border: none; background: none; cursor: pointer; }
    .gc-ports { display: grid; grid-template-columns: 1fr 1fr; padding-block: 8px; }
    .gc-in, .gc-out { list-style: none; margin: 0; padding: 0; display: grid; grid-auto-rows: 22px; }
    .gc-out { justify-items: end; }
    .gc-port { display: inline-flex; align-items: center; gap: .25rem; border: none; background: none; padding: 0;
               font-size: .75rem; cursor: crosshair; color: inherit; }
    .gc-port--in { margin-inline-start: -5px; }
    .gc-port--out { margin-inline-end: -5px; }
    .gc-dot { inline-size: 10px; block-size: 10px; border-radius: 50%; border: 2px solid var(--color-text-secondary, #888);
              background: var(--color-bg, #fff); box-sizing: border-box; }
    .gc-ptype { font-family: ui-monospace, monospace; font-size: .625rem; color: var(--color-text-secondary, #888); }
    .gc-port--ok .gc-dot { border-color: var(--color-success, #2f855a); background: var(--color-success-bg, #e6f4ea); }
    .gc-port--no { opacity: .45; }
    .gc-port--armed .gc-dot { border-color: var(--color-primary, #2b6cb0); background: var(--color-primary, #2b6cb0); }
    .gc-group { position: absolute; box-sizing: border-box; border: 1px dashed var(--color-text-secondary, #999);
                border-radius: 10px; background: color-mix(in srgb, var(--color-primary, #2b6cb0) 4%, transparent); }
    .gc-group--selected { border-style: solid; border-color: var(--color-primary, #2b6cb0); }
    .gc-group-label { position: absolute; inset-block-start: 2px; inset-inline-start: .5rem; border: none; background: none;
                      font-size: .75rem; font-weight: 600; cursor: pointer; color: inherit; }
    .gc-note { position: absolute; inline-size: 12rem; min-block-size: 4rem; resize: both; border: 1px solid var(--color-warning-border, var(--color-border));
               background: var(--color-warning-bg, var(--color-bg)); border-radius: 6px; padding: .375rem; font: inherit; font-size: .8125rem; }
    .gc-group-edit { display: flex; gap: .5rem; align-items: center; }
  `],
})
export class GraphCanvasComponent {
  /** The graph to edit. */
  readonly doc = input.required<GraphDoc>();
  /** The node types and their typed ports. */
  readonly kinds = input.required<readonly GraphNodeKind[]>();
  /** The designer's rendering of a node's header detail, given `$implicit` (the node). */
  readonly nodeTemplate = input<TemplateRef<unknown> | null>(null);
  /** Node types that stand for another flow; they get an open button. */
  readonly subflowTypes = input<readonly string[]>(['sub_workflow']);
  /** View only: no moves, connections or edits. */
  readonly readonly = input(false);
  /** Marks on node cards, by node id. */
  readonly nodeMarks = input<Readonly<Record<string, readonly GraphNodeMark[]>>>({});
  /** The edges to light (`edgeKey`), a simulated path. */
  readonly litEdges = input<readonly string[]>([]);
  /** Connections may go back to an earlier node (a state model). */
  readonly allowCycles = input(false);
  /** Only connections are edited: no adding or removing nodes, groups or notes, no save. */
  readonly edgesOnly = input(false);

  /** Save: the commands since the last save. */
  readonly save = output<EditCommand[]>();
  /** The graph after every change. */
  readonly changed = output<GraphDoc>();
  /** The selected node, `null` when none. */
  readonly nodeSelected = output<string | null>();
  /** A sub-flow node's open button. */
  readonly openSubflow = output<GraphDocNode>();

  readonly cardWidth = CARD.width;
  readonly stack = signal(new CommandStack<GraphDoc>({ nodes: [], edges: [] }));
  readonly selectedNodes = signal<string[]>([]);
  readonly selectedEdge = signal<number | null>(null);
  readonly selectedGroup = signal<string | null>(null);
  readonly pending = signal<Pending | null>(null);
  readonly refusal = signal<Refusal | null>(null);
  readonly drag = signal<Drag | null>(null);

  private readonly kindMap = computed(() => new Map(this.kinds().map(k => [k.type, k])));

  readonly cards = computed(() => {
    const d = this.drag();
    return this.stack().doc().nodes.map(node => {
      const kind = this.kindMap().get(node.type);
      const moving = d && d.id === node.id;
      return {
        node, kind,
        x: node.ports.x + (moving ? d.dx : 0),
        y: node.ports.y + (moving ? d.dy : 0),
        height: cardHeight(kind),
      };
    });
  });

  /** Where each node is drawn (a dragged node at its moving place). */
  private readonly drawn = computed(() => new Map(this.cards().map(c => [
    c.node.id, { ...c.node, ports: { ...c.node.ports, x: c.x, y: c.y } } as GraphDocNode,
  ])));

  readonly wires = computed(() => {
    const drawn = this.drawn();
    return this.stack().doc().edges.flatMap((e: GraphDocEdge, index: number) => {
      const a = drawn.get(e.from_node);
      const b = drawn.get(e.to_node);
      if (!a || !b) return [];
      const d = wirePath(
        portPoint(a, this.kindMap().get(a.type), 'out', e.from_port),
        portPoint(b, this.kindMap().get(b.type), 'in', e.to_port),
      );
      return [{ key: edgeKey(e), index, d }];
    });
  });

  readonly pendingWire = computed(() => {
    const p = this.pending();
    if (!p) return null;
    const a = this.drawn().get(p.from.node);
    if (!a) return null;
    return wirePath(portPoint(a, this.kindMap().get(a.type), 'out', p.from.port), { x: p.x, y: p.y });
  });

  readonly notes = computed(() => this.stack().doc().notes ?? []);

  readonly groupBoxes = computed(() => {
    const doc = { ...this.stack().doc(), nodes: [...this.drawn().values()] };
    return (doc.groups ?? []).flatMap(group => {
      const box = groupBox(doc, this.kinds(), group);
      return box ? [{ group, box }] : [];
    });
  });

  readonly extent = computed(() => {
    const cards = this.cards();
    const notes = this.notes();
    const width = Math.max(800, ...cards.map(c => c.x + CARD.width + 80), ...notes.map(n => n.x + 260));
    const height = Math.max(480, ...cards.map(c => c.y + c.height + 80), ...notes.map(n => n.y + 160));
    return { width, height };
  });

  constructor() {
    effect(() => {
      const doc = this.doc();
      untracked(() => {
        this.stack.set(new CommandStack(structuredClone(doc)));
        this.selectedNodes.set([]);
        this.selectedEdge.set(null);
        this.selectedGroup.set(null);
        this.pending.set(null);
      });
    });
  }

  private rtl(): boolean {
    return typeof document !== 'undefined' && document.documentElement.dir === 'rtl';
  }

  outputs(kind: GraphNodeKind | undefined) {
    return outputsOf(kind);
  }

  marksOf(id: string): readonly GraphNodeMark[] {
    return this.nodeMarks()[id] ?? [];
  }

  /** The tones as one attribute (`[data-marks~=…]`), null when none. */
  tonesOf(id: string): string | null {
    return this.marksOf(id).map(m => m.tone).join(' ') || null;
  }

  /** A card's accessible name: its label and what its marks say. */
  cardLabel(label: string, id: string): string {
    return [label, ...this.marksOf(id).map(m => m.note)].join('. ');
  }

  /** A mark is never colour alone. */
  symbol(tone: GraphNodeMark['tone']): string {
    return { problem: '!', ran: '✓', active: '…', failed: '✕', skipped: '–', uncovered: '○', initial: '▸' }[tone];
  }

  private connectionCheck(from: PortRef, to: PortRef): Refusal | null {
    return checkConnection(this.stack().doc(), this.kinds(), from, to, { allowCycles: this.allowCycles() });
  }

  /** Applies one command and reports the change. */
  exec(command: EditCommand): boolean {
    if (this.readonly() || !this.stack().exec(command)) return false;
    this.changed.emit(this.stack().doc());
    return true;
  }

  /** Applies commands in order, stopping at the first that does not apply. */
  execAll(commands: readonly EditCommand[]): boolean {
    for (const c of commands) if (!this.exec(c)) return false;
    return true;
  }

  /** Adds a node of `type` at (`x`, `y`); answers its id. */
  addNode(type: string, x: number, y: number, config: Record<string, unknown> = {}): string | null {
    const doc = this.stack().doc();
    const id = freshId(doc, `${type}_`);
    const ok = this.exec({ op: 'add', path: '/nodes/-', value: { id, type, config, ports: { x, y } } });
    if (!ok) return null;
    this.selectNode(id);
    return id;
  }

  undo(): void {
    if (!this.readonly() && this.stack().undo()) this.afterHistory();
  }

  redo(): void {
    if (!this.readonly() && this.stack().redo()) this.afterHistory();
  }

  emitSave(): void {
    this.save.emit(this.stack().takeUnsaved());
  }

  selectNode(id: string, event?: MouseEvent): void {
    event?.stopPropagation();
    const add = !!event && (event.ctrlKey || event.metaKey);
    this.selectedNodes.update(s => (add ? (s.includes(id) ? s.filter(n => n !== id) : [...s, id]) : [id]));
    this.selectedEdge.set(null);
    this.selectedGroup.set(null);
    this.nodeSelected.emit(this.selectedNodes().at(-1) ?? null);
  }

  selectEdge(index: number, event: Event): void {
    event.stopPropagation();
    this.selectedEdge.set(index);
    this.selectedNodes.set([]);
    this.selectedGroup.set(null);
    this.nodeSelected.emit(null);
  }

  selectGroup(id: string, event: Event): void {
    event.stopPropagation();
    this.selectedGroup.set(id);
    this.selectedEdge.set(null);
  }

  onBackground(event: MouseEvent): void {
    if (event.target !== event.currentTarget && !(event.target as Element).classList?.contains('gc-plane')) return;
    this.clearSelection();
  }

  private clearSelection(): void {
    this.selectedNodes.set([]);
    this.selectedEdge.set(null);
    this.selectedGroup.set(null);
    this.pending.set(null);
    this.refusal.set(null);
    this.nodeSelected.emit(null);
  }

  // ── Moving ────────────────────────────────────────────────────────────────

  startDrag(event: PointerEvent, id: string): void {
    if (this.readonly() || event.button !== 0) return;
    const index = this.stack().doc().nodes.findIndex(n => n.id === id);
    if (index < 0) return;
    this.drag.set({ id, index, startX: event.clientX, startY: event.clientY, dx: 0, dy: 0 });
  }

  onPointerMove(event: PointerEvent): void {
    const d = this.drag();
    if (d) {
      const sx = (event.clientX - d.startX) * (this.rtl() ? -1 : 1);
      this.drag.set({ ...d, dx: sx, dy: event.clientY - d.startY });
      return;
    }
    const p = this.pending();
    if (p) {
      const plane = (event.currentTarget as HTMLElement).firstElementChild as HTMLElement | null;
      const rect = plane?.getBoundingClientRect();
      if (!rect) return;
      const x = this.rtl() ? rect.right - event.clientX : event.clientX - rect.left;
      this.pending.set({ ...p, x, y: event.clientY - rect.top });
    }
  }

  onPointerUp(): void {
    const d = this.drag();
    if (!d) return;
    this.drag.set(null);
    if (d.dx === 0 && d.dy === 0) return;
    const doc = this.stack().doc();
    const node = doc.nodes[d.index];
    this.exec(moveNodeCommand(doc, d.index, node.ports.x + d.dx, node.ports.y + d.dy));
  }

  // ── Connecting ────────────────────────────────────────────────────────────

  isArmed(node: string, port: string): boolean {
    const p = this.pending();
    return !!p && p.from.node === node && p.from.port === port;
  }

  arm(node: string, port: string, event: PointerEvent): void {
    event.stopPropagation();
    if (this.readonly()) return;
    const n = this.drawn().get(node);
    if (!n) return;
    const at = portPoint(n, this.kindMap().get(n.type), 'out', port);
    this.pending.set({ from: { node, port }, x: at.x, y: at.y });
    this.refusal.set(null);
  }

  /** Click (or Enter) on an output: arm it, or disarm it when it is armed. */
  toggleArm(node: string, port: string, event: MouseEvent): void {
    event.stopPropagation();
    if (this.readonly()) return;
    // A pointer press already armed it; a click without one (keyboard) arms here.
    if (event.detail === 0) {
      if (this.isArmed(node, port)) this.pending.set(null);
      else this.arm(node, port, event as unknown as PointerEvent);
    }
  }

  /** Whether the pending connection may end on this input. */
  accepts(node: string, port: string): boolean {
    const p = this.pending();
    return !!p && this.connectionCheck(p.from, { node, port }) === null;
  }

  hoverInput(node: string, port: string): void {
    const p = this.pending();
    if (!p) return;
    this.refusal.set(this.connectionCheck(p.from, { node, port }));
  }

  /** Ends the pending connection on an input: made, or refused with the reason. */
  finishAt(node: string, port: string, event: Event): void {
    event.stopPropagation();
    const p = this.pending();
    if (!p) return;
    const refusal = this.connectionCheck(p.from, { node, port });
    this.pending.set(null);
    if (refusal) {
      this.refusal.set(refusal);
      return;
    }
    this.refusal.set(null);
    this.exec(connectCommand(p.from, { node, port }));
  }

  // ── Groups and notes ──────────────────────────────────────────────────────

  groupIndex(id: string): number {
    return (this.stack().doc().groups ?? []).findIndex(g => g.id === id) + 1;
  }

  groupLabel(index: number): string {
    return this.stack().doc().groups?.[index]?.label ?? '';
  }

  groupSelection(): void {
    const nodes = this.selectedNodes();
    if (!nodes.length) return;
    const doc = this.stack().doc();
    const id = freshId(doc, 'group_');
    const count = (doc.groups ?? []).length + 1;
    if (!this.execAll([...ensureLists(doc), { op: 'add', path: '/groups/-', value: { id, label: `${count}`, nodes: [...nodes] } }])) return;
    this.selectedGroup.set(id);
  }

  renameGroup(index: number, event: Event): void {
    const label = (event.target as HTMLInputElement).value.trim();
    if (label) this.exec({ op: 'set', path: `/groups/${index}/label`, value: label });
  }

  ungroup(index: number): void {
    if (this.exec({ op: 'remove', path: `/groups/${index}` })) this.selectedGroup.set(null);
  }

  addNote(): void {
    const doc = this.stack().doc();
    const id = freshId(doc, 'note_');
    const y = Math.max(16, ...this.cards().map(c => c.y + c.height + 24), ...this.notes().map(n => n.y + 96));
    this.execAll([...ensureLists(doc), { op: 'add', path: '/notes/-', value: { id, text: '', x: 16, y } }]);
  }

  setNote(index: number, event: Event): void {
    this.exec({ op: 'set', path: `/notes/${index}/text`, value: (event.target as HTMLTextAreaElement).value });
  }

  openSub(node: GraphDocNode, event: Event): void {
    event.stopPropagation();
    this.openSubflow.emit(node);
  }

  // ── Keyboard ──────────────────────────────────────────────────────────────

  onKey(event: KeyboardEvent): void {
    const target = event.target as HTMLElement | null;
    if (target && (target.tagName === 'TEXTAREA' || target.tagName === 'INPUT')) return;
    const mod = event.ctrlKey || event.metaKey;
    const key = event.key;
    if (mod && key.toLowerCase() === 'z' && !event.shiftKey) { event.preventDefault(); this.undo(); return; }
    if (mod && (key.toLowerCase() === 'y' || (key.toLowerCase() === 'z' && event.shiftKey))) { event.preventDefault(); this.redo(); return; }
    if (key === 'Escape') { this.clearSelection(); return; }
    if (key === 'Delete' || key === 'Backspace') {
      const edge = this.selectedEdge();
      if (edge !== null) {
        event.preventDefault();
        if (this.exec({ op: 'remove', path: `/edges/${edge}` })) this.selectedEdge.set(null);
        return;
      }
      const nodes = this.selectedNodes();
      if (nodes.length && !this.edgesOnly()) {
        event.preventDefault();
        for (const id of nodes) this.execAll(removeNodeCommands(this.stack().doc(), id));
        this.selectedNodes.set([]);
        this.nodeSelected.emit(null);
      }
      return;
    }
    const step = event.altKey ? 64 : 8;
    const moves: Record<string, [number, number]> = {
      ArrowUp: [0, -step], ArrowDown: [0, step],
      ArrowLeft: [this.rtl() ? step : -step, 0], ArrowRight: [this.rtl() ? -step : step, 0],
    };
    const delta = moves[key];
    const focus = this.selectedNodes().at(-1);
    if (delta && focus) {
      event.preventDefault();
      const doc = this.stack().doc();
      const index = doc.nodes.findIndex(n => n.id === focus);
      if (index < 0) return;
      const node = doc.nodes[index];
      this.exec(moveNodeCommand(doc, index, node.ports.x + delta[0], node.ports.y + delta[1]));
    }
  }

  private afterHistory(): void {
    const doc = this.stack().doc();
    const ids = new Set(doc.nodes.map(n => n.id));
    this.selectedNodes.update(s => s.filter(id => ids.has(id)));
    if ((this.selectedEdge() ?? -1) >= doc.edges.length) this.selectedEdge.set(null);
    this.changed.emit(doc);
  }
}
