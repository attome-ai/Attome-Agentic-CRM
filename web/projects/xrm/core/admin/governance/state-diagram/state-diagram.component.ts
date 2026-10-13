import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { TranslatePipe } from '@attome/base';

/** The part of a transition the diagram draws. */
export interface DiagramEdge {
  from_state: string;
  to_state:   string;
  name:       string;
}

interface NodeView { state: string; x: number; y: number; lx: number; ly: number; anchor: string; initial: boolean; }
interface EdgeView { key: string; d: string; name: string; }

const SIZE = 360;
const CENTER = SIZE / 2;
const RADIUS = 120;
const NODE_R = 9;
/** How far an edge bows away from the straight line, so A->B and B->A
 * (whose perpendiculars point opposite ways) never overlap. */
const BOW = 18;

let nextId = 0;

/**
 * U8 — a read-only preview of a state model: the states on a circle, one
 * curved arrow per transition, the initial state ringed. It draws what is
 * saved; editing happens in the transitions table beside it. The same
 * transitions are listed as text in the table, so this is a visual aid,
 * not the only way to read the model.
 */
@Component({
  selector: 'attome-state-diagram',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrl: './state-diagram.component.css',
  templateUrl: './state-diagram.component.html',
})
export class StateDiagramComponent {
  readonly states = input<readonly string[]>([]);
  readonly transitions = input<readonly DiagramEdge[]>([]);
  readonly initial = input<string>('');

  readonly size = SIZE;
  readonly nodeR = NODE_R;
  readonly markerId = `attome-state-arrow-${nextId++}`;

  /** Every state named by the choice field or by a transition, in order. */
  readonly allStates = computed(() => {
    const seen = new Set<string>();
    const out: string[] = [];
    const add = (s: string) => { if (s && !seen.has(s)) { seen.add(s); out.push(s); } };
    this.states().forEach(add);
    this.transitions().forEach(t => { add(t.from_state); add(t.to_state); });
    return out;
  });

  readonly nodes = computed<NodeView[]>(() => {
    const list = this.allStates();
    const n = list.length;
    return list.map((state, i) => {
      // Start at the top and go clockwise.
      const angle = n === 1 ? -Math.PI / 2 : -Math.PI / 2 + (2 * Math.PI * i) / n;
      const x = CENTER + RADIUS * Math.cos(angle);
      const y = CENTER + RADIUS * Math.sin(angle);
      const lx = CENTER + (RADIUS + NODE_R + 8) * Math.cos(angle);
      const ly = CENTER + (RADIUS + NODE_R + 8) * Math.sin(angle) + 4;
      const cos = Math.cos(angle);
      const anchor = Math.abs(cos) < 0.3 ? 'middle' : cos > 0 ? 'start' : 'end';
      return { state, x, y, lx, ly, anchor, initial: state === this.initial() };
    });
  });

  readonly edges = computed<EdgeView[]>(() => {
    const pos = new Map(this.nodes().map(nv => [nv.state, nv]));
    const out: EdgeView[] = [];
    for (const t of this.transitions()) {
      const a = pos.get(t.from_state);
      const b = pos.get(t.to_state);
      if (!a || !b || a === b) continue;
      const dx = b.x - a.x;
      const dy = b.y - a.y;
      const len = Math.hypot(dx, dy) || 1;
      const ux = dx / len;
      const uy = dy / len;
      // Perpendicular bow for the control point.
      const cx = (a.x + b.x) / 2 - uy * BOW;
      const cy = (a.y + b.y) / 2 + ux * BOW;
      // Trim both ends to the node circles (the arrow head sits on b's edge).
      const sx = a.x + ux * NODE_R;
      const sy = a.y + uy * NODE_R;
      const ex = b.x - ux * (NODE_R + 2);
      const ey = b.y - uy * (NODE_R + 2);
      out.push({
        key: `${t.from_state}->${t.to_state}`,
        d: `M${sx.toFixed(1)},${sy.toFixed(1)} Q${cx.toFixed(1)},${cy.toFixed(1)} ${ex.toFixed(1)},${ey.toFixed(1)}`,
        name: t.name,
      });
    }
    return out;
  });
}
