import { ChangeDetectionStrategy, Component, computed, effect, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import {
  AdminService, AttributeMeta, EntityDetail, EntityMeta, ImpactChange, ImpactReport, LineageService,
  RelationshipDef,
} from '@attome/xrm/core/admin/data';
import { DraftReviewComponent } from './draft-review.component';

/** Where a node sits relative to the entity in the middle. */
export type DiagramRole = 'center' | 'lookup' | 'base' | 'derived' | 'related';

export interface DiagramNode {
  logicalname: string;
  label: string;
  role: DiagramRole;
  x: number;
  y: number;
}

export interface DiagramEdge {
  from: string;
  to: string;
  /** `extends` edges are drawn dashed. */
  kind: 'lookup' | 'extends' | 'relationship';
  label: string;
}

export interface Diagram {
  nodes: DiagramNode[];
  edges: DiagramEdge[];
  width: number;
  height: number;
}

export const DIAGRAM_WIDTH = 900;
const NODE_W = 170;
const ROW = 56;
const TOP = 40;

/**
 * The neighbourhood of `center` as a diagram: what it looks up on the
 * inline end, its many-to-many partners on the inline start, the entity it
 * extends above and the entities extending it below. In a right-to-left
 * language every x is mirrored, so the inline sides swap. Pure.
 */
export function layoutDiagram(
  center: EntityMeta,
  detail: EntityDetail | null,
  all: readonly EntityMeta[],
  relationships: readonly RelationshipDef[],
  rtl: boolean,
): Diagram {
  const byId = new Map(all.map(e => [e.id, e]));
  const byName = new Map(all.map(e => [e.logicalname, e]));
  const label = (name: string) => byName.get(name)?.name ?? name;
  const nodes: DiagramNode[] = [];
  const edges: DiagramEdge[] = [];
  const seen = new Set<string>([center.logicalname]);

  const lookups: { target: string; field: string }[] = [];
  for (const a of detail?.attributes ?? []) {
    const target = a.lookup_entity_name;
    if (a.is_active && target && target !== center.logicalname) lookups.push({ target, field: a.name });
  }
  const lookupTargets = [...new Set(lookups.map(l => l.target))];
  const related = relationships
    .filter(r => r.is_active && (r.entity_a === center.logicalname || r.entity_b === center.logicalname))
    .map(r => ({ other: r.entity_a === center.logicalname ? r.entity_b : r.entity_a, name: r.name }))
    .filter(r => r.other !== center.logicalname);
  const relatedTargets = [...new Set(related.map(r => r.other))];
  const base = center.extends_entity_id ? byId.get(center.extends_entity_id) ?? null : null;
  const derived = all.filter(e => e.extends_entity_id === center.id);

  const sideRows = Math.max(lookupTargets.length, relatedTargets.length, 1);
  const middleY = TOP + (base ? ROW * 1.5 : 0);
  const sidesTop = middleY - ((sideRows - 1) * ROW) / 2;
  const derivedY = Math.max(middleY + ROW * 1.5, sidesTop + sideRows * ROW + ROW * 0.5);
  const height = (derived.length ? derivedY : Math.max(middleY, sidesTop + (sideRows - 1) * ROW)) + ROW;
  const x = (logical: number) => (rtl ? DIAGRAM_WIDTH - logical : logical);
  const place = (logicalname: string, role: DiagramRole, lx: number, y: number) => {
    nodes.push({ logicalname, label: label(logicalname), role, x: x(lx), y });
    seen.add(logicalname);
  };

  place(center.logicalname, 'center', DIAGRAM_WIDTH / 2, middleY);
  if (base) {
    place(base.logicalname, 'base', DIAGRAM_WIDTH / 2, TOP);
    edges.push({ from: center.logicalname, to: base.logicalname, kind: 'extends', label: '' });
  }
  lookupTargets.forEach((target, i) => {
    if (!seen.has(target)) place(target, 'lookup', DIAGRAM_WIDTH - NODE_W / 2 - 10, sidesTop + i * ROW);
    edges.push({
      from: center.logicalname, to: target, kind: 'lookup',
      label: lookups.filter(l => l.target === target).map(l => l.field).join(', '),
    });
  });
  relatedTargets.forEach((other, i) => {
    if (!seen.has(other)) place(other, 'related', NODE_W / 2 + 10, sidesTop + i * ROW);
    edges.push({
      from: center.logicalname, to: other, kind: 'relationship',
      label: related.filter(r => r.other === other).map(r => r.name).join(', '),
    });
  });
  const step = DIAGRAM_WIDTH / (derived.length + 1);
  derived.forEach((d, i) => {
    if (!seen.has(d.logicalname)) place(d.logicalname, 'derived', step * (i + 1), derivedY);
    edges.push({ from: d.logicalname, to: center.logicalname, kind: 'extends', label: '' });
  });
  return { nodes, edges, width: DIAGRAM_WIDTH, height };
}

/** Catalogue keys, spelled out so the catalogue coverage check sees each one. */
const CHANGE_KEYS: Record<Exclude<ImpactChange, 'other'>, string> = {
  delete: 'dataModel.change_delete',
  rename: 'dataModel.change_rename',
  retype: 'dataModel.change_retype',
};

/**
 * A1-T14 — the data model as a diagram, and the designer panel beside it.
 *
 * - Pick an entity: it sits in the middle with what it looks up on the
 *   inline end, its many-to-many partners on the inline start, the entity
 *   it extends above and the entities extending it below (`extends` edges
 *   dashed). Clicking a node moves the middle to it. The layout mirrors in
 *   Arabic.
 * - The designer panel lists the entity's attributes with type,
 *   sensitivity, lookup target and what it extends.
 * - Before a delete, rename or type change, "What uses this" asks the
 *   lineage impact route (`GET /api/v1/admin/lineage/impact`) and lists the
 *   forms, flows, reports, metrics and integrations affected, and what would
 *   break.
 *
 * Read only: changes made from the designer belong in Develop-mode drafts,
 * which do not exist yet, so nothing here writes to the running model.
 */
@Component({
  selector: 'xrm-data-model-diagram',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, DraftReviewComponent],
  styleUrls: ['../../../../styles/admin-page.css'],
  styles: [`
    .dm { display: grid; grid-template-columns: minmax(0, 2fr) minmax(16rem, 1fr); gap: 1rem; }
    @media (max-width: 900px) { .dm { grid-template-columns: minmax(0, 1fr); } }
    .dm-svg { inline-size: 100%; block-size: auto; border: 1px solid var(--color-border); border-radius: 6px; }
    .dm-node rect { fill: var(--color-bg-alt); stroke: var(--color-text-secondary); }
    .dm-node[data-role='center'] rect { stroke-width: 2; stroke: var(--color-accent); }
    .dm-node { cursor: pointer; }
    .dm-node text { font-size: 12px; dominant-baseline: middle; text-anchor: middle; }
    .dm-edge { stroke: var(--color-text-secondary); }
    .dm-edge[data-kind='extends'] { stroke-dasharray: 6 4; }
    .dm-edge-label { font-size: 10px; fill: var(--color-text-secondary); text-anchor: middle; }
    .dm-panel table { inline-size: 100%; border-collapse: collapse; }
    .dm-panel td, .dm-panel th { padding-block: .25rem; padding-inline: .4rem; text-align: start; }
    .dm-uses { margin-block-start: .75rem; }
    .dm-actions { display: flex; gap: .25rem; flex-wrap: wrap; }
  `],
  template: `
    <section>
      <header class="page-header">
        <div>
          <h2>{{ 'dataModel.title' | translate }}</h2>
          <p class="subtitle">{{ 'dataModel.subtitle' | translate }}</p>
        </div>
      </header>
      <label>
        {{ 'dataModel.entity' | translate }}
        <select data-testid="dm-entity" [ngModel]="centerName()" (ngModelChange)="centerName.set($event)">
          @for (e of entities(); track e.id) { <option [value]="e.logicalname">{{ e.name }}</option> }
        </select>
      </label>
      @if (error(); as e) { <p role="alert">{{ e }}</p> }
      <div class="dm">
        @if (diagram(); as d) {
          <svg class="dm-svg" data-testid="dm-svg" [attr.viewBox]="'0 0 ' + d.width + ' ' + d.height" role="img"
               [attr.aria-label]="'dataModel.diagramLabel' | translate">
            @for (edge of d.edges; track edge.from + edge.to + edge.kind) {
              @if (pos(d, edge.from); as a) { @if (pos(d, edge.to); as b) {
                <line class="dm-edge" [attr.data-kind]="edge.kind" [attr.x1]="a.x" [attr.y1]="a.y" [attr.x2]="b.x" [attr.y2]="b.y" />
                @if (edge.label) {
                  <text class="dm-edge-label" [attr.x]="(a.x + b.x) / 2" [attr.y]="(a.y + b.y) / 2 - 4">{{ edge.label }}</text>
                }
              } }
            }
            @for (n of d.nodes; track n.logicalname) {
              <g class="dm-node" data-testid="dm-node" [attr.data-role]="n.role" [attr.data-name]="n.logicalname"
                 [attr.data-x]="n.x" tabindex="0" role="button" [attr.aria-label]="n.label"
                 (click)="centerName.set(n.logicalname)" (keydown.enter)="centerName.set(n.logicalname)">
                <rect [attr.x]="n.x - 85" [attr.y]="n.y - 18" width="170" height="36" rx="6" />
                <text [attr.x]="n.x" [attr.y]="n.y">{{ n.label }}</text>
              </g>
            }
          </svg>
        }
        <aside class="dm-panel" data-testid="dm-panel">
          @if (detail(); as det) {
            <h2>{{ det.name }} <bdi dir="ltr">{{ det.logicalname }}</bdi></h2>
            <p>{{ 'dataModel.storage' | translate }}: {{ det.storage_mode }}
              @if (baseName(); as b) { · {{ 'dataModel.extends' | translate }} {{ b }} }</p>
            <div class="dm-actions">
              <button type="button" data-testid="dm-entity-uses" (click)="checkUses(null, 'delete')">
                {{ 'dataModel.usesEntity' | translate }}</button>
            </div>
            <p class="subtitle">{{ 'dataModel.readOnly' | translate }}</p>
            <table>
              <thead><tr>
                <th>{{ 'dataModel.attribute' | translate }}</th><th>{{ 'dataModel.type' | translate }}</th>
                <th>{{ 'dataModel.sensitivity' | translate }}</th><th></th>
              </tr></thead>
              <tbody>
                @for (a of attributes(); track a.id) {
                  <tr data-testid="dm-attribute">
                    <td>{{ a.name }} <bdi dir="ltr">{{ a.logicalname }}</bdi></td>
                    <td><bdi dir="ltr">{{ a.field_type }}</bdi>
                      @if (a.lookup_entity_name) { → <bdi dir="ltr">{{ a.lookup_entity_name }}</bdi> }</td>
                    <td>{{ sensitivityOf(a) }}</td>
                    <td class="dm-actions">
                      @for (c of changes; track c) {
                        <button type="button" [attr.data-testid]="'dm-uses-' + c" (click)="checkUses(a, c)">{{ changeKey(c) | translate }}</button>
                      }
                    </td>
                  </tr>
                }
              </tbody>
            </table>
            @if (impact(); as i) {
              <section class="dm-uses" data-testid="dm-uses" aria-live="polite">
                <h3>{{ 'dataModel.usesTitle' | translate: { target: impactTarget() } }}</h3>
                @if (!i.affected.length && !i.breaking.length) {
                  <p>{{ 'dataModel.usesNone' | translate }}</p>
                }
                @if (i.breaking.length) {
                  <h4>{{ 'dataModel.breaking' | translate }}</h4>
                  <ul data-breaking>
                    @for (b of i.breaking; track b.from_kind + b.from_ref) { <li>{{ b.from_label }} ({{ b.from_kind }})</li> }
                  </ul>
                }
                @if (i.affected.length) {
                  <h4>{{ 'dataModel.affected' | translate }}</h4>
                  <ul data-affected>
                    @for (u of i.affected; track u.from_kind + u.from_ref) { <li>{{ u.from_label }} ({{ u.from_kind }}, {{ u.edge_kind }})</li> }
                  </ul>
                }
                @if (i.hidden) { <p>{{ 'dataModel.hidden' | translate: { n: i.hidden } }}</p> }
              </section>
            }
          } @else {
            <p>{{ 'dataModel.pick' | translate }}</p>
          }
        </aside>
      </div>
      <!-- AD1-T2: a building agent's draft, reviewed before anything is made. -->
      <xrm-draft-review />
    </section>
  `,
})
export class DataModelDiagramComponent {
  private readonly admin = inject(AdminService);
  private readonly lineage = inject(LineageService);
  private readonly lang = inject(LangService);

  readonly changes: readonly Exclude<ImpactChange, 'other'>[] = ['delete', 'rename', 'retype'];
  readonly entities = signal<EntityMeta[]>([]);
  readonly relationships = signal<RelationshipDef[]>([]);
  readonly centerName = signal<string | null>(null);
  readonly detail = signal<EntityDetail | null>(null);
  readonly impact = signal<ImpactReport | null>(null);
  readonly impactTarget = signal('');
  readonly error = signal<string | null>(null);

  readonly center = computed(() => this.entities().find(e => e.logicalname === this.centerName()) ?? null);
  readonly attributes = computed(() => (this.detail()?.attributes ?? []).filter(a => a.is_active));
  readonly baseName = computed(() => {
    const id = this.detail()?.extends_entity_id;
    return id ? this.entities().find(e => e.id === id)?.name ?? null : null;
  });
  readonly diagram = computed(() => {
    const c = this.center();
    return c ? layoutDiagram(c, this.detail(), this.entities(), this.relationships(), this.lang.isRtl()) : null;
  });

  constructor() {
    this.admin.listEntities().subscribe({
      next: list => {
        const sorted = [...list].sort((a, b) => a.name.localeCompare(b.name));
        this.entities.set(sorted);
        if (!this.centerName() && sorted.length) this.centerName.set(sorted[0].logicalname);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.admin.listRelationships().subscribe({
      next: list => this.relationships.set(list),
      error: () => this.relationships.set([]),
    });
    effect(() => {
      const c = this.center();
      this.impact.set(null);
      if (!c) { this.detail.set(null); return; }
      this.admin.getEntity(c.id).subscribe({
        next: d => this.detail.set(d),
        error: (e: ApiError) => this.error.set(e.message),
      });
    });
  }

  pos(d: Diagram, name: string): DiagramNode | undefined {
    return d.nodes.find(n => n.logicalname === name);
  }

  changeKey(c: Exclude<ImpactChange, 'other'>): string {
    return CHANGE_KEYS[c];
  }

  sensitivityOf(a: AttributeMeta): string {
    return a.sensitivity ?? a.data_classification;
  }

  /** What uses the entity, or one attribute, before `change`. */
  checkUses(attribute: AttributeMeta | null, change: ImpactChange): void {
    const d = this.detail();
    if (!d) return;
    this.impactTarget.set(attribute ? `${d.logicalname}.${attribute.logicalname}` : d.logicalname);
    this.lineage.impact(d.logicalname, attribute?.logicalname ?? null, change).subscribe({
      next: report => this.impact.set(report),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
