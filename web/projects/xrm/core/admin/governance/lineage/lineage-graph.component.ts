import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import type { LineageComparison, LineageDirection, LineageGraph } from '@attome/xrm/core/admin/data';

import { NODE_H, NODE_W, layoutLineage } from './lineage-layout';

let nextId = 0;

/**
 * L5-T7: one lineage walk drawn as columns of boxes with curved arrows in
 * the direction data flows, in the state diagram's style (the same arrow
 * marker and stroke). A definition that reads personal data, and the
 * arrows into it, are red; in compare mode an edge added since the older
 * version is marked. Choosing a box walks from it instead (`open`). The
 * drawing mirrors in right to left; every node is also a button in reading
 * order, so the graph is never the only way to read it.
 */
@Component({
  selector: 'xrm-lineage-graph',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrl: './lineage.component.css',
  template: `
    @if (layout().nodes.length === 0) {
      <p class="lg-empty" data-lineage-empty>{{ 'governance.lineage.empty' | translate }}</p>
    } @else {
      <div class="lg-canvas">
        <svg class="lg" data-lineage-svg [attr.viewBox]="viewBox()" [attr.width]="layout().width + 2 * pad"
             [attr.height]="layout().height + 2 * pad" role="img"
             [attr.aria-label]="'governance.lineage.graphAria' | translate: { nodes: layout().nodes.length, edges: layout().edges.length }">
          <defs>
            @for (m of markers; track m.id) {
              <marker [attr.id]="m.id" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                <path [class]="'lg-arrow ' + m.cls" d="M0,0 L10,5 L0,10 z" />
              </marker>
            }
          </defs>
          @for (e of layout().edges; track e.key) {
            <path class="lg-edge" data-lineage-edge [attr.d]="e.path"
                  [class.lg-edge--sensitive]="e.sensitive" [class.lg-edge--added]="e.added"
                  [class.lg-edge--guess]="e.edge.confidence === 'entity_only'"
                  [attr.marker-end]="'url(#' + markerFor(e.sensitive, e.added) + ')'">
              <title>{{ e.edge.edge_kind }} · {{ e.edge.confidence }}</title>
            </path>
          }
          @for (n of layout().nodes; track n.node.key) {
            <g class="lg-node" data-lineage-node [attr.data-key]="n.node.key"
               [class.lg-node--sensitive]="n.sensitive" [class.lg-node--start]="n.start"
               tabindex="0" role="button" [attr.aria-label]="n.node.label"
               (click)="open.emit(n.node.key)" (keydown.enter)="open.emit(n.node.key)">
              <rect [attr.x]="n.x" [attr.y]="n.y" [attr.width]="nodeW" [attr.height]="nodeH" rx="6" />
              <text [attr.x]="n.x + 8" [attr.y]="n.y + 16" class="lg-node__kind">{{ kindOf(n.node.key) }}</text>
              <text [attr.x]="n.x + 8" [attr.y]="n.y + 31" class="lg-node__label">{{ clip(n.node.label) }}</text>
              <title>{{ n.node.label }}</title>
            </g>
          }
        </svg>
      </div>
      <ul class="lg-list" [attr.aria-label]="'governance.lineage.nodesList' | translate">
        @for (n of layout().nodes; track n.node.key) {
          <li>
            <button type="button" class="btn-text" data-lineage-open [attr.data-key]="n.node.key" (click)="open.emit(n.node.key)">
              {{ n.node.label }}
            </button>
            <span class="hint cell-mono" dir="ltr">{{ n.node.key }}</span>
            @if (n.sensitive) { <span class="badge lg-badge--sensitive">{{ 'governance.lineage.personal' | translate }}</span> }
          </li>
        }
      </ul>
    }
  `,
})
export class LineageGraphComponent {
  readonly graph = input.required<LineageGraph>();
  readonly direction = input<LineageDirection>('down');
  readonly rtl = input(false);
  readonly comparison = input<LineageComparison | null>(null);
  /** A node chosen to walk from. */
  readonly open = output<string>();

  readonly nodeW = NODE_W;
  readonly nodeH = NODE_H;
  readonly pad = 12;
  private readonly id = nextId++;
  readonly markers = [
    { id: `lg-arrow-${this.id}`, cls: '' },
    { id: `lg-arrow-red-${this.id}`, cls: 'lg-arrow--sensitive' },
    { id: `lg-arrow-new-${this.id}`, cls: 'lg-arrow--added' },
  ];

  readonly layout = computed(() => layoutLineage(this.graph(), this.direction(), this.rtl(), this.comparison()));
  readonly viewBox = computed(() => {
    const l = this.layout();
    return `${-this.pad} ${-this.pad} ${l.width + 2 * this.pad} ${l.height + 2 * this.pad}`;
  });

  markerFor(sensitive: boolean, added: boolean): string {
    return this.markers[sensitive ? 1 : added ? 2 : 0].id;
  }

  kindOf(key: string): string {
    return key.slice(0, key.indexOf(':'));
  }

  /** A label short enough for its box. */
  clip(label: string): string {
    return label.length > 24 ? `${label.slice(0, 23)}…` : label;
  }
}
