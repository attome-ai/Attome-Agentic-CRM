import { ChangeDetectionStrategy, Component, computed, input, output, signal } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import {
  checkConnection, outputsOf, type GraphDoc, type GraphDocEdge, type GraphDocNode, type GraphNodeKind,
  type GraphPortSpec, type PortRef, type Refusal,
} from '@attome/xrm/canvas';

/** A node the selected one can take a value from, with its typed outputs. */
export interface EarlierNode {
  node: GraphDocNode;
  outputs: GraphPortSpec[];
  /** Already upstream of the selected node; otherwise not connected to it yet. */
  upstream: boolean;
}

function walk(edges: readonly GraphDocEdge[], start: string, step: (e: GraphDocEdge) => [string, string]): Set<string> {
  const found = new Set<string>();
  const stack = [start];
  while (stack.length) {
    const at = stack.pop() as string;
    for (const e of edges) {
      const [here, there] = step(e);
      if (here === at && !found.has(there)) { found.add(there); stack.push(there); }
    }
  }
  return found;
}

/**
 * Every node whose outputs the selected node can take: its upstream nodes
 * first, then those not connected to it yet. A node downstream of it is left
 * out (connecting it would make a loop), and so is the node itself. Pure.
 */
export function earlierNodes(doc: GraphDoc, kinds: readonly GraphNodeKind[], id: string): EarlierNode[] {
  const upstream = walk(doc.edges, id, e => [e.to_node, e.from_node]);
  const downstream = walk(doc.edges, id, e => [e.from_node, e.to_node]);
  const list = doc.nodes
    .filter(n => n.id !== id && (upstream.has(n.id) || !downstream.has(n.id)))
    .map(node => ({
      node,
      outputs: outputsOf(kinds.find(k => k.type === node.type)),
      upstream: upstream.has(node.id),
    }));
  return [...list.filter(n => n.upstream), ...list.filter(n => !n.upstream)];
}

/**
 * M2-T2 — the data-mapping panel beside the settings form: the selected
 * node's inputs, what feeds each one, and every earlier node's typed outputs.
 * Drag an output onto an input, or choose an output and then an input (this
 * works from the keyboard); either makes the same edge the canvas makes, under
 * the same checks, and a refusal says why. In this engine a node's input is
 * the value an edge carries, so the panel maps ports; a Map Fields node's
 * `mapping` setting reaches inside a JSON value.
 */
@Component({
  selector: 'xrm-mapping-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="mp" data-testid="mapping-panel" [attr.aria-label]="'workflowDesigner.mapping.title' | translate">
      <h4>{{ 'workflowDesigner.mapping.inputs' | translate }}</h4>
      @if (inputs().length === 0) { <p class="mp-muted">{{ 'workflowDesigner.mapping.noInputs' | translate }}</p> }
      <ul class="mp-list">
        @for (i of inputs(); track i.port.name) {
          <li class="mp-input" data-testid="mp-input-row" [attr.data-port]="i.port.name">
            <button type="button" class="mp-target" data-testid="mp-input" [attr.data-port]="i.port.name"
                    [disabled]="readonly()" [class.mp-ok]="armed() && accepts(i.port.name)"
                    [class.mp-no]="armed() && !accepts(i.port.name)"
                    [attr.aria-label]="(i.port.required ? 'workflowDesigner.mapping.inputRequired' : 'workflowDesigner.mapping.input') | translate: { port: i.port.name, type: i.port.portType }"
                    (click)="finish(i.port.name)" (dragover)="over(i.port.name, $event)" (dragleave)="refusal.set(null)"
                    (drop)="drop(i.port.name, $event)">
              {{ i.port.name }}@if (i.port.required) {<span aria-hidden="true"> *</span>}
              <span class="mp-type">{{ i.port.portType }}</span>
            </button>
            @for (s of i.sources; track s.index) {
              <span class="mp-source" data-testid="mp-source">
                <bdi dir="ltr">{{ s.edge.from_node }}.{{ s.edge.from_port }}</bdi>
                @if (!readonly()) {
                  <button type="button" class="mp-remove" data-testid="mp-remove"
                          [attr.aria-label]="'workflowDesigner.mapping.remove' | translate: { from: s.edge.from_node + '.' + s.edge.from_port }"
                          (click)="disconnect.emit(s.index)">×</button>
                }
              </span>
            } @empty {
              <span class="mp-muted" data-testid="mp-unmapped">{{ 'workflowDesigner.mapping.unmapped' | translate }}</span>
            }
          </li>
        }
      </ul>
      <p class="mp-status" role="status" aria-live="polite" data-testid="mp-status">
        @if (refusal(); as r) { {{ r.key | translate: r.params }} }
        @else if (armed()) { {{ 'workflowDesigner.mapping.chooseInput' | translate }} }
      </p>
      <h4>{{ 'workflowDesigner.mapping.earlier' | translate }}</h4>
      @for (e of earlier(); track e.node.id) {
        <div class="mp-node" data-testid="mp-node" [attr.data-node]="e.node.id">
          <p class="mp-node-name">
            {{ labelOf()(e.node.type) }} <bdi class="mp-id" dir="ltr">{{ e.node.id }}</bdi>
            @if (!e.upstream) { <span class="mp-muted"> {{ 'workflowDesigner.mapping.notConnected' | translate }}</span> }
          </p>
          <ul class="mp-list">
            @for (p of e.outputs; track p.name) {
              <li>
                <button type="button" class="mp-output" data-testid="mp-output" [attr.data-port]="p.name"
                        [disabled]="readonly()" [draggable]="!readonly()"
                        [attr.aria-pressed]="isArmed(e.node.id, p.name)" [class.mp-armed]="isArmed(e.node.id, p.name)"
                        (click)="toggle(e.node.id, p.name)" (dragstart)="start(e.node.id, p.name, $event)"
                        (dragend)="armed.set(null)">
                  {{ p.name }} <span class="mp-type">{{ p.portType }}</span>
                </button>
              </li>
            }
          </ul>
        </div>
      } @empty {
        <p class="mp-muted">{{ 'workflowDesigner.mapping.noEarlier' | translate }}</p>
      }
    </section>
  `,
  styles: [`
    .mp { display: grid; gap: .375rem; border-block-start: 1px solid var(--color-border, #ddd); padding-block-start: .5rem; font-size: .8125rem; }
    .mp h4 { margin: 0; font-size: .8125rem; }
    .mp-list { list-style: none; margin: 0; padding: 0; display: grid; gap: .25rem; }
    .mp-input { display: flex; flex-wrap: wrap; gap: .25rem; align-items: center; }
    .mp-target, .mp-output { display: inline-flex; gap: .375rem; align-items: center; border: 1px solid var(--color-border, #ccc);
                             border-radius: 6px; background: var(--color-bg, #fff); padding: .125rem .375rem; font-size: .75rem; color: inherit; }
    .mp-output { cursor: grab; }
    .mp-armed { border-color: var(--color-primary, #2b6cb0); box-shadow: 0 0 0 2px var(--color-primary-bg, #dbe8f7); }
    .mp-ok { border-color: var(--color-success, #2f855a); background: var(--color-success-bg, #e6f4ea); }
    .mp-no { opacity: .55; }
    .mp-type { font-family: ui-monospace, monospace; font-size: .625rem; color: var(--color-text-secondary, #777); }
    .mp-source { display: inline-flex; gap: .25rem; align-items: center; font-family: ui-monospace, monospace; font-size: .7rem;
                 background: var(--color-bg-alt, #eef2f7); border-radius: 999px; padding-inline: .375rem; }
    .mp-remove { border: none; background: none; cursor: pointer; padding: 0; color: inherit; }
    .mp-node-name { margin: 0; }
    .mp-id { font-family: ui-monospace, monospace; font-size: .7rem; color: var(--color-text-secondary, #777); }
    .mp-muted { color: var(--color-text-secondary, #666); font-size: .75rem; margin: 0; }
    .mp-status { margin: 0; min-block-size: 1rem; font-size: .75rem; color: var(--color-text-secondary, #555); }
  `],
})
export class MappingPanelComponent {
  readonly doc = input.required<GraphDoc>();
  readonly kinds = input.required<readonly GraphNodeKind[]>();
  /** The selected node. */
  readonly nodeId = input.required<string>();
  readonly readonly = input(false);
  /** A node type's translated name. */
  readonly labelOf = input<(type: string) => string>(t => t);

  /** Make this edge; the panel has already checked it. */
  readonly connect = output<{ from: PortRef; to: PortRef }>();
  /** Remove the edge at this index of the graph's edges. */
  readonly disconnect = output<number>();

  readonly armed = signal<PortRef | null>(null);
  readonly refusal = signal<Refusal | null>(null);

  readonly inputs = computed(() => {
    const doc = this.doc();
    const id = this.nodeId();
    const node = doc.nodes.find(n => n.id === id);
    const kind = node ? this.kinds().find(k => k.type === node.type) : undefined;
    return (kind?.inputs ?? []).map(port => ({
      port,
      sources: doc.edges.flatMap((edge, index) =>
        edge.to_node === id && edge.to_port === port.name ? [{ edge, index }] : []),
    }));
  });

  readonly earlier = computed(() => earlierNodes(this.doc(), this.kinds(), this.nodeId()));

  isArmed(node: string, port: string): boolean {
    const a = this.armed();
    return !!a && a.node === node && a.port === port;
  }

  private check(port: string): Refusal | null {
    const from = this.armed();
    return from ? checkConnection(this.doc(), this.kinds(), from, { node: this.nodeId(), port }) : null;
  }

  accepts(port: string): boolean {
    return this.check(port) === null;
  }

  toggle(node: string, port: string): void {
    if (this.readonly()) return;
    this.refusal.set(null);
    this.armed.set(this.isArmed(node, port) ? null : { node, port });
  }

  start(node: string, port: string, event: DragEvent): void {
    if (this.readonly()) { event.preventDefault(); return; }
    this.refusal.set(null);
    this.armed.set({ node, port });
    event.dataTransfer?.setData('text/plain', `${node}.${port}`);
  }

  /** Lets the drop land on an input and says why it would be refused. */
  over(port: string, event: DragEvent): void {
    event.preventDefault();
    this.refusal.set(this.check(port));
  }

  drop(port: string, event: DragEvent): void {
    event.preventDefault();
    this.finish(port);
  }

  /** Ends on an input: the edge is made, or refused with the reason. */
  finish(port: string): void {
    const from = this.armed();
    if (!from || this.readonly()) return;
    const refusal = this.check(port);
    this.armed.set(null);
    this.refusal.set(refusal);
    if (!refusal) this.connect.emit({ from, to: { node: this.nodeId(), port } });
  }
}
