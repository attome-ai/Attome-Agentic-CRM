import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { type GraphDoc, type GraphDocNode, type GraphNodeMark } from '@attome/xrm/canvas';

/**
 * The nodes in running order: each after the nodes that feed it, the graph's
 * own order breaking ties; a node on a loop comes last, not lost. Pure.
 */
export function stepOrder(doc: GraphDoc): GraphDocNode[] {
  const waiting = new Map(doc.nodes.map(n => [n.id, 0]));
  for (const e of doc.edges) {
    if (waiting.has(e.to_node) && waiting.has(e.from_node)) waiting.set(e.to_node, (waiting.get(e.to_node) ?? 0) + 1);
  }
  const out: GraphDocNode[] = [];
  const left = [...doc.nodes];
  while (left.length) {
    const at = left.findIndex(n => waiting.get(n.id) === 0);
    const [node] = left.splice(at < 0 ? 0 : at, 1);
    out.push(node);
    for (const e of doc.edges) {
      if (e.from_node === node.id && waiting.has(e.to_node)) waiting.set(e.to_node, (waiting.get(e.to_node) ?? 0) - 1);
    }
  }
  return out;
}

/**
 * M2-T4 — the flow as a list of steps, which phones open by default: the
 * canvas needs more width than a phone has. Selecting a step opens its
 * settings, as on the canvas.
 */
@Component({
  selector: 'xrm-step-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <ol class="sl" data-testid="step-list">
      @for (s of steps(); track s.node.id) {
        <li>
          <button type="button" class="sl-step" data-testid="step-item" [attr.data-node]="s.node.id"
                  [class.sl-step--selected]="s.node.id === selected()" [attr.aria-current]="s.node.id === selected() ? 'step' : null"
                  (click)="picked.emit(s.node.id)">
            <span class="sl-name">{{ labelOf()(s.node.type) }}</span>
            <bdi class="sl-id" dir="ltr">{{ s.node.id }}</bdi>
            @for (m of s.marks; track m.tone) { <span class="sl-note" data-testid="step-note">{{ m.note }}</span> }
            @if (s.next.length) {
              <span class="sl-next">{{ 'workflowDesigner.steps.next' | translate }} <bdi dir="ltr">{{ s.next.join(', ') }}</bdi></span>
            }
          </button>
        </li>
      } @empty {
        <li class="sl-note">{{ 'workflowDesigner.steps.empty' | translate }}</li>
      }
    </ol>
  `,
  styles: [`
    .sl { margin: 0; padding-inline-start: 1.5rem; display: grid; gap: .375rem; }
    .sl-step { inline-size: 100%; min-block-size: 2.75rem; display: grid; gap: .125rem; text-align: start; padding: .5rem;
               border: 1px solid var(--color-border, #ddd); border-radius: 8px; background: var(--color-bg, #fff); color: inherit; }
    .sl-step--selected { border-color: var(--color-primary, #2b6cb0); box-shadow: 0 0 0 2px var(--color-primary-bg, #dbe8f7); }
    .sl-name { font-weight: 600; }
    .sl-id { font-family: ui-monospace, monospace; font-size: .7rem; color: var(--color-text-secondary, #777); }
    .sl-next { font-size: .75rem; color: var(--color-text-secondary, #666); }
    .sl-note { font-size: .75rem; color: var(--color-danger, #c53030); }
  `],
})
export class StepListComponent {
  readonly doc = input.required<GraphDoc>();
  readonly selected = input<string | null>(null);
  readonly marks = input<Readonly<Record<string, readonly GraphNodeMark[]>>>({});
  readonly labelOf = input<(type: string) => string>(t => t);
  readonly picked = output<string>();

  readonly steps = computed(() => {
    const doc = this.doc();
    return stepOrder(doc).map(node => ({
      node,
      marks: (this.marks()[node.id] ?? []).filter(m => m.tone === 'problem' || m.tone === 'failed'),
      next: [...new Set(doc.edges.filter(e => e.from_node === node.id).map(e => e.to_node))],
    }));
  });
}
