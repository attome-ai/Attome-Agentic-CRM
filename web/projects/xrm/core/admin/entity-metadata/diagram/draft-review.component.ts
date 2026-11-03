import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, SdkService, TranslatePipe } from '@attome/base';

/** One drafted entity's decision, as `model.draft`'s plan gives it (AD1-T1). */
export interface DraftStep {
  entity: string;
  decision: 'create' | 'extend' | 'reuse' | 'ask';
  base?: string;
  existing?: string;
  question?: string;
  add_attributes: string[];
  ask_attributes: { attribute: string; near: string }[];
}

/** One build-tool call the plan makes. */
export interface DraftCall {
  action: string;
  args: Record<string, unknown>;
}

/** What `model.draft` answers. */
export interface DraftResult {
  plan: DraftStep[];
  calls: DraftCall[];
  findings: { entity: string; attribute: string | null; code: string; message: string }[];
}

const ENTITY_CREATE = 'model.entity.create';
const DIAGRAM_WIDTH = 900;

/** A node of the draft's diagram. */
export interface DraftNode {
  logicalname: string;
  label: string;
  /** `proposed` for a drafted entity, `base` for the library entity it extends or reuses. */
  role: 'proposed' | 'base';
  x: number;
  y: number;
}

/** An edge from a drafted entity to the entity it extends or reuses. */
export interface DraftEdge {
  from: string;
  to: string;
  kind: 'extends' | 'reuses';
}

export interface DraftDiagram {
  nodes: DraftNode[];
  edges: DraftEdge[];
  width: number;
  height: number;
}
const ROW = 90;
const TOP = 40;

/** The key a rejected entity or attribute is kept under. Pure. */
export function entityKey(entity: string): string {
  return `entity:${entity}`;
}

export function attributeKey(entity: string, attribute: string): string {
  return `attribute:${entity}.${attribute}`;
}

/** The step a call belongs to. Pure. */
function stepOf(result: DraftResult, call: DraftCall): DraftStep | undefined {
  const target = String(call.args['entity'] ?? call.args['logicalname'] ?? '');
  return result.plan.find(s =>
    call.action === ENTITY_CREATE
      ? s.entity === target
      : s.entity === target || (s.decision === 'reuse' && s.existing === target));
}

/**
 * The calls left once the person rejected `rejected` (entities and
 * attributes by [`entityKey`] / [`attributeKey`]): a rejected entity takes
 * its attributes with it. Pure.
 */
export function acceptedCalls(result: DraftResult, rejected: ReadonlySet<string>): DraftCall[] {
  return result.calls.filter(call => {
    const step = stepOf(result, call);
    if (!step || rejected.has(entityKey(step.entity))) return false;
    if (call.action === ENTITY_CREATE) return true;
    return !rejected.has(attributeKey(step.entity, String(call.args['logicalname'] ?? '')));
  });
}

/**
 * The draft as a diagram: the proposed entities in a row, and below them the
 * library entities they extend or reuse, joined by an edge. In a
 * right-to-left language every x is mirrored. Pure.
 */
export function layoutDraft(result: DraftResult, rtl: boolean): DraftDiagram {
  const steps = result.plan;
  const span = (count: number) => DIAGRAM_WIDTH / (count + 1);
  const x = (logical: number) => (rtl ? DIAGRAM_WIDTH - logical : logical);
  const nodes: DraftNode[] = steps.map((s, i) => ({
    logicalname: s.entity,
    label: s.entity,
    role: 'proposed' as const,
    x: x(span(steps.length) * (i + 1)),
    y: TOP,
  }));
  const targets = [...new Set(steps.map(s => s.base ?? s.existing).filter((t): t is string => !!t))];
  targets.forEach((t, i) => nodes.push({
    logicalname: t,
    label: t,
    role: 'base' as const,
    x: x(span(targets.length) * (i + 1)),
    y: TOP + ROW,
  }));
  const edges: DraftEdge[] = steps
    .filter(s => s.base || s.existing)
    .map(s => ({
      from: s.entity,
      to: (s.base ?? s.existing) as string,
      kind: (s.base ? 'extends' : 'reuses') as DraftEdge['kind'],
    }));
  return { nodes, edges, width: DIAGRAM_WIDTH, height: TOP + ROW * 2 };
}

const DECISION_KEYS: Record<DraftStep['decision'], string> = {
  create: 'dataModel.decision_create',
  extend: 'dataModel.decision_extend',
  reuse: 'dataModel.decision_reuse',
  ask: 'dataModel.decision_ask',
};

/**
 * AD1-T2 — a building agent's draft, reviewed before anything is made: the
 * proposed entities on a diagram beside the entities they extend or reuse,
 * each entity and attribute accepted or rejected, then the accepted
 * build-tool calls made one by one (each a confirmed `model.entity.create`
 * or `model.attribute.create`, in the Develop workspace the tab works in).
 */
@Component({
  selector: 'xrm-draft-review',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styles: [`
    .dr { display: grid; gap: .75rem; margin-block-start: 1rem; }
    .dr textarea { inline-size: 100%; min-block-size: 4rem; }
    .dr-svg { inline-size: 100%; max-block-size: 260px; }
    .dr-svg [data-role='proposed'] rect { fill: var(--color-info-bg, var(--color-bg)); stroke: var(--color-primary, currentColor); }
    .dr-svg [data-role='base'] rect { fill: var(--color-bg); stroke: var(--color-text-secondary); }
    .dr-svg text { font-size: 12px; dominant-baseline: middle; text-anchor: middle; }
    .dr-svg line { stroke: var(--color-text-secondary); }
    .dr-svg line[data-kind='extends'] { stroke-dasharray: 6 4; }
    .dr-steps { list-style: none; padding: 0; display: grid; gap: .5rem; }
    .dr-attrs { list-style: none; padding-inline-start: 1.5rem; }
    .dr-rejected { opacity: .55; }
  `],
  template: `
    <section class="dr" data-testid="draft-review">
      <h3>{{ 'dataModel.draftTitle' | translate }}</h3>
      <label>
        {{ 'dataModel.draftDescribe' | translate }}
        <textarea data-testid="draft-description" [ngModel]="description()" (ngModelChange)="description.set($event)"></textarea>
      </label>
      <div>
        <button type="button" data-testid="draft-run" (click)="draft()" [disabled]="busy() || !description().trim()">
          {{ 'dataModel.draftButton' | translate }}</button>
      </div>
      @if (error(); as e) { <p role="alert">{{ e }}</p> }
      @if (result(); as r) {
        @if (diagram(); as d) {
          <svg class="dr-svg" data-testid="draft-svg" [attr.viewBox]="'0 0 ' + d.width + ' ' + d.height" role="img"
               [attr.aria-label]="'dataModel.draftDiagram' | translate">
            @for (edge of d.edges; track edge.from + edge.to) {
              @if (pos(d, edge.from); as a) { @if (pos(d, edge.to); as b) {
                <line [attr.data-kind]="edge.kind" [attr.x1]="a.x" [attr.y1]="a.y" [attr.x2]="b.x" [attr.y2]="b.y" />
              } }
            }
            @for (n of d.nodes; track n.logicalname) {
              <g data-testid="draft-node" [attr.data-role]="n.role" [attr.data-name]="n.logicalname"
                 [class.dr-rejected]="isRejected(entityKey(n.logicalname))">
                <rect [attr.x]="n.x - 80" [attr.y]="n.y - 18" width="160" height="36" rx="6" />
                <text [attr.x]="n.x" [attr.y]="n.y">{{ n.label }}</text>
              </g>
            }
          </svg>
        }
        <ul class="dr-steps">
          @for (s of r.plan; track s.entity) {
            <li data-testid="draft-step" [attr.data-entity]="s.entity">
              <label>
                <input type="checkbox" [checked]="!isRejected(entityKey(s.entity)) && s.decision !== 'ask'"
                       [disabled]="s.decision === 'ask'" (change)="toggle(entityKey(s.entity))" />
                <bdi dir="ltr">{{ s.entity }}</bdi> — {{ decisionKey(s.decision) | translate: { target: s.base ?? s.existing ?? '' } }}
              </label>
              @if (s.question) { <p>{{ s.question }}</p> }
              <ul class="dr-attrs">
                @for (a of s.add_attributes; track a) {
                  <li>
                    <label>
                      <input type="checkbox" [checked]="!isRejected(attributeKey(s.entity, a))"
                             [disabled]="isRejected(entityKey(s.entity)) || s.decision === 'ask'"
                             (change)="toggle(attributeKey(s.entity, a))" />
                      <bdi dir="ltr">{{ a }}</bdi>
                    </label>
                  </li>
                }
                @for (q of s.ask_attributes; track q.attribute) {
                  <li>{{ 'dataModel.nearAttribute' | translate: { attribute: q.attribute, near: q.near } }}</li>
                }
              </ul>
            </li>
          }
        </ul>
        <p>{{ 'dataModel.accepted' | translate: { n: accepted().length } }}</p>
        <button type="button" data-testid="draft-apply" (click)="apply()" [disabled]="busy() || !accepted().length">
          {{ 'dataModel.apply' | translate }}</button>
        @if (applied() > 0) { <p aria-live="polite">{{ 'dataModel.applied' | translate: { n: applied() } }}</p> }
      }
    </section>
  `,
})
export class DraftReviewComponent {
  private readonly sdk = inject(SdkService);
  private readonly lang = inject(LangService);

  readonly description = signal('');
  readonly result = signal<DraftResult | null>(null);
  readonly rejected = signal<ReadonlySet<string>>(new Set());
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly applied = signal(0);

  readonly accepted = computed(() => {
    const r = this.result();
    return r ? acceptedCalls(r, this.rejected()) : [];
  });
  readonly diagram = computed(() => {
    const r = this.result();
    return r ? layoutDraft(r, this.lang.isRtl()) : null;
  });

  readonly entityKey = entityKey;
  readonly attributeKey = attributeKey;

  decisionKey(decision: DraftStep['decision']): string {
    return DECISION_KEYS[decision];
  }

  pos(d: DraftDiagram, name: string): DraftNode | undefined {
    return d.nodes.find(n => n.logicalname === name);
  }

  isRejected(key: string): boolean {
    return this.rejected().has(key);
  }

  toggle(key: string): void {
    const next = new Set(this.rejected());
    if (next.has(key)) next.delete(key);
    else next.add(key);
    this.rejected.set(next);
  }

  draft(): void {
    this.busy.set(true);
    this.error.set(null);
    this.applied.set(0);
    this.sdk.post<{ result: DraftResult }>('/api/v1/actions/model.draft/invoke', {
      body: { args: { description: this.description().trim() } },
    }).subscribe({
      next: outcome => {
        this.busy.set(false);
        this.rejected.set(new Set());
        this.result.set(outcome.result);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.message);
      },
    });
  }

  /** Makes the accepted calls one by one, stopping at the first refusal. */
  apply(): void {
    const calls = this.accepted();
    this.busy.set(true);
    this.error.set(null);
    this.applied.set(0);
    const next = (i: number): void => {
      if (i >= calls.length) {
        this.busy.set(false);
        return;
      }
      this.sdk.post(`/api/v1/actions/${calls[i].action}/invoke`, {
        body: { args: calls[i].args, confirm: true },
      }).subscribe({
        next: () => {
          this.applied.set(i + 1);
          next(i + 1);
        },
        error: (e: ApiError) => {
          this.busy.set(false);
          this.error.set(e.message);
        },
      });
    };
    next(0);
  }
}
