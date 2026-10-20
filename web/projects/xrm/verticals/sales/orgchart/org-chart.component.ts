import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { entityFormRoute } from '@attome/xrm/core/entity';
import { catchError, of } from 'rxjs';

import { OrgChart, OrgChartService, OrgNode } from './orgchart.service';

/** A card's size and the gaps between cards, in chart units. */
export const CARD_W = 180;
export const CARD_H = 72;
const GAP_X = 24;
const LEVEL_H = 112;

/** A card where the layout put it. */
export interface PlacedCard {
  node: OrgNode;
  x: number;
  y: number;
  depth: number;
}

/** A connector from a manager's card to a report's. */
export interface Connector {
  from: string;
  to: string;
  path: string;
}

/** The laid-out chart. */
export interface ChartLayout {
  cards: PlacedCard[];
  connectors: Connector[];
  width: number;
  height: number;
}

/**
 * Lays the trees out top-down: each leaf takes the next slot, a manager is
 * centred over their reports, and roots sit side by side. In right to left
 * the x axis is mirrored, so the first report is on the right. Pure.
 */
export function layoutChart(roots: readonly OrgNode[], rtl: boolean): ChartLayout {
  const cards: PlacedCard[] = [];
  let next = 0;
  let deepest = 0;
  const place = (node: OrgNode, depth: number): number => {
    deepest = Math.max(deepest, depth);
    let x: number;
    if (node.children.length === 0) {
      x = next;
      next += CARD_W + GAP_X;
    } else {
      const xs = node.children.map(child => place(child, depth + 1));
      x = (xs[0] + xs[xs.length - 1]) / 2;
    }
    cards.push({ node, x, y: depth * LEVEL_H, depth });
    return x;
  };
  for (const root of roots) place(root, 0);
  const width = Math.max(0, next - GAP_X);
  if (rtl) for (const c of cards) c.x = width - c.x - CARD_W;
  const at = new Map(cards.map(c => [c.node.id, c]));
  const connectors: Connector[] = [];
  for (const c of cards) {
    for (const child of c.node.children) {
      const to = at.get(child.id);
      if (!to) continue;
      const x1 = c.x + CARD_W / 2;
      const y1 = c.y + CARD_H;
      const x2 = to.x + CARD_W / 2;
      const y2 = to.y;
      const mid = (y1 + y2) / 2;
      connectors.push({ from: c.node.id, to: child.id, path: `M${x1},${y1} V${mid} H${x2} V${y2}` });
    }
  }
  const height = cards.length ? deepest * LEVEL_H + CARD_H : 0;
  return { cards, connectors, width, height };
}

/** Whether `node` or anyone under it matches `query` (name, title or department). Pure. */
export function matches(node: OrgNode, query: string): boolean {
  const q = query.trim().toLocaleLowerCase();
  if (!q) return false;
  return [node.full_name, node.job_title, node.department, node.department_ar]
    .some(v => !!v && v.toLocaleLowerCase().includes(q));
}

/** Whether `manager` is `node` or reports (at any depth) to `node`. Pure. */
export function isUnder(roots: readonly OrgNode[], node: string, manager: string): boolean {
  const find = (list: readonly OrgNode[]): OrgNode | null => {
    for (const n of list) {
      if (n.id === node) return n;
      const hit = find(n.children);
      if (hit) return hit;
    }
    return null;
  };
  const start = find(roots);
  if (!start) return node === manager;
  const walk = (n: OrgNode): boolean => n.id === manager || n.children.some(walk);
  return walk(start);
}

/** The last move, kept so it can be undone. */
interface Move {
  contact: string;
  name: string;
  previous: string | null;
}

/**
 * The account org chart (roadmap D23-T11): people as cards from top to
 * bottom along who they report to, with connectors; branches past three
 * levels collapse to a count and open on request; a search highlights
 * matching cards; zoom; the whole group's chart; the unplaced people below.
 * Dragging a card onto another makes the second the first's manager
 * (`PUT /api/v1/sales/contacts/{id}/manager` with the contact's row version)
 * and offers to undo it. Former employees are greyed. Arabic mirrors the
 * chart and the page. Shown only to people who may read the account's
 * contacts; the route is the sales module's.
 */
@Component({
  selector: 'xrm-sales-org-chart',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    <section class="oc" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="oc-title" data-testid="oc">
      <header class="oc-head">
        <h2 id="oc-title">{{ 'salesOrgChart.title' | translate }}
          @for (c of companies(); track c.id) { <span class="oc-company">{{ c.name }}</span> }
        </h2>
        <div class="oc-tools">
          <label>{{ 'salesOrgChart.search' | translate }}
            <input type="search" data-testid="oc-search" [value]="query()" (input)="query.set(text($event))"></label>
          <label class="oc-check"><input type="checkbox" data-testid="oc-group" [checked]="group()" (change)="toggleGroup()">
            {{ 'salesOrgChart.group' | translate }}</label>
          <button type="button" (click)="zoomBy(-0.1)" [attr.aria-label]="'salesOrgChart.zoomOut' | translate">−</button>
          <span dir="ltr" data-testid="oc-zoom">{{ zoomPercent() }}%</span>
          <button type="button" (click)="zoomBy(0.1)" [attr.aria-label]="'salesOrgChart.zoomIn' | translate">+</button>
          <a [routerLink]="newContact" [queryParams]="{ account_ref: id() }" data-testid="oc-add">{{ 'salesOrgChart.addPerson' | translate }}</a>
        </div>
      </header>
      @if (error(); as message) { <p class="oc-error" role="alert">{{ message }}</p> }
      @if (undo(); as move) {
        <div class="oc-undo" role="status" data-testid="oc-undo">
          {{ 'salesOrgChart.moved' | translate }} <strong>{{ move.name }}</strong>
          <button type="button" data-testid="oc-undo-button" (click)="undoMove()">{{ 'salesOrgChart.undo' | translate }}</button>
        </div>
      }

      <div class="oc-canvas" [style.--oc-zoom]="zoom()">
        <!-- The layout mirrors x itself, so the drawing plane is always left to right. -->
        <div class="oc-plane" dir="ltr" [style.--oc-w]="layout().width + 'px'" [style.--oc-h]="layout().height + 'px'">
          <svg class="oc-lines" [attr.viewBox]="'0 0 ' + layout().width + ' ' + layout().height" aria-hidden="true">
            @for (l of layout().connectors; track l.from + l.to) { <path [attr.d]="l.path" /> }
          </svg>
          @for (c of layout().cards; track c.node.id) {
            <article class="oc-card" draggable="true" data-testid="oc-card" [attr.data-id]="c.node.id"
                     [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'"
                     [class.oc-former]="c.node.is_former_employee" [class.oc-hit]="hit(c.node)"
                     [style.--oc-x]="c.x + 'px'" [style.--oc-y]="c.y + 'px'"
                     (dragstart)="dragStart(c.node)" (dragover)="$event.preventDefault()" (drop)="dropOn($event, c.node)">
              <strong>{{ c.node.full_name }}</strong>
              @if (c.node.job_title) { <span>{{ c.node.job_title }}</span> }
              @if (department(c.node); as d) { <span class="oc-dept">{{ d }}</span> }
              @if (c.node.collapsed_children) {
                <button type="button" class="oc-more" (click)="open(c.node.id)">
                  +<span dir="ltr">{{ c.node.collapsed_children }}</span> {{ 'salesOrgChart.more' | translate }}
                </button>
              }
            </article>
          }
        </div>
      </div>

      @if (unplaced().length) {
        <h3>{{ 'salesOrgChart.unplaced' | translate }}</h3>
        <div class="oc-unplaced" data-testid="oc-unplaced">
          @for (n of unplaced(); track n.id) {
            <article class="oc-card oc-static" draggable="true" [class.oc-former]="n.is_former_employee"
                     (dragstart)="dragStart(n)" (dragover)="$event.preventDefault()" (drop)="dropOn($event, n)">
              <strong>{{ n.full_name }}</strong>
              @if (n.job_title) { <span>{{ n.job_title }}</span> }
            </article>
          }
        </div>
      }
    </section>
  `,
  styles: [`
    .oc { display: grid; gap: var(--space-3, .75rem); }
    .oc-head, .oc-tools { display: flex; flex-wrap: wrap; gap: var(--space-2, .5rem); align-items: center; justify-content: space-between; }
    .oc-company { margin-inline-start: .5rem; color: var(--color-text-secondary, #666); font-size: .875em; }
    .oc-canvas { overflow: auto; border: 1px solid var(--color-border, #ddd); border-radius: 6px; padding: var(--space-3, .75rem); }
    .oc-plane { position: relative; inline-size: var(--oc-w); block-size: var(--oc-h);
                transform: scale(var(--oc-zoom, 1)); transform-origin: top center; }
    .oc-lines { position: absolute; inset-block-start: 0; inset-inline-start: 0; inline-size: var(--oc-w); block-size: var(--oc-h); }
    .oc-lines path { fill: none; stroke: var(--color-border, #bbb); stroke-width: 1.5; }
    .oc-card { position: absolute; inset-block-start: var(--oc-y); inset-inline-start: var(--oc-x);
               inline-size: 180px; min-block-size: 72px; box-sizing: border-box; padding: .375rem .5rem;
               display: grid; gap: 2px; font-size: .8125rem; cursor: grab;
               background: var(--color-bg, #fff); border: 1px solid var(--color-border, #ccc); border-radius: 6px; }
    .oc-card.oc-static { position: static; }
    .oc-card.oc-former { opacity: .55; }
    .oc-card.oc-hit { outline: 2px solid var(--color-primary, #2b6cb0); }
    .oc-dept { color: var(--color-text-secondary, #666); }
    .oc-more { justify-self: start; font-size: .75rem; }
    .oc-unplaced { display: flex; flex-wrap: wrap; gap: var(--space-2, .5rem); }
    .oc-undo { display: flex; gap: .5rem; align-items: center; padding: .5rem .75rem; border-radius: 6px;
               background: var(--color-bg-alt, #f4f4f4); }
    .oc-error { color: var(--color-danger, #c53030); }
  `],
})
export class OrgChartComponent {
  private readonly service = inject(OrgChartService);
  protected readonly lang = inject(LangService);
  protected readonly newContact = entityFormRoute('contact');

  /** The account (route parameter). */
  readonly id = input.required<string>();

  protected readonly chart = signal<OrgChart | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly group = signal(false);
  protected readonly query = signal('');
  protected readonly zoom = signal(1);
  protected readonly expand = signal<string[]>([]);
  protected readonly undo = signal<Move | null>(null);
  private dragged: OrgNode | null = null;

  protected readonly companies = computed(() => this.chart()?.companies ?? []);
  protected readonly unplaced = computed(() => this.chart()?.unplaced ?? []);
  protected readonly layout = computed(() => layoutChart(this.chart()?.roots ?? [], this.lang.isRtl()));
  protected readonly zoomPercent = computed(() => Math.round(this.zoom() * 100));

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => this.load(id));
    });
  }

  protected text(event: Event): string {
    return (event.target as HTMLInputElement).value;
  }

  protected hit(node: OrgNode): boolean {
    return matches(node, this.query());
  }

  protected department(node: OrgNode): string | null {
    return (this.lang.isRtl() && node.department_ar) || node.department || null;
  }

  protected toggleGroup(): void {
    this.group.update(g => !g);
    this.load(this.id());
  }

  protected zoomBy(step: number): void {
    this.zoom.update(z => Math.min(2, Math.max(0.3, Math.round((z + step) * 10) / 10)));
  }

  protected open(node: string): void {
    this.expand.update(list => (list.includes(node) ? list : [...list, node]));
    this.load(this.id());
  }

  protected dragStart(node: OrgNode): void {
    this.dragged = node;
  }

  protected dropOn(event: Event, target: OrgNode): void {
    event.preventDefault();
    const moved = this.dragged;
    this.dragged = null;
    if (!moved || moved.id === target.id) return;
    // A person cannot report to someone who reports to them.
    if (isUnder(this.chart()?.roots ?? [], moved.id, target.id)) {
      this.error.set(this.lang.translate('salesOrgChart.loop'));
      return;
    }
    this.setManager(moved.id, target.id, moved.full_name ?? '', true);
  }

  protected undoMove(): void {
    const move = this.undo();
    if (!move) return;
    this.undo.set(null);
    this.setManager(move.contact, move.previous, move.name, false);
  }

  private setManager(contact: string, manager: string | null, name: string, offerUndo: boolean): void {
    this.error.set(null);
    this.service.setManager(contact, manager).pipe(
      catchError((e: unknown) => {
        this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(answer => {
      if (!answer) return;
      if (offerUndo) this.undo.set({ contact, name, previous: answer.previous_manager_id ?? null });
      this.load(this.id());
    });
  }

  private load(id: string): void {
    this.service.chart(id, this.group(), this.expand()).pipe(
      catchError((e: unknown) => {
        this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(chart => {
      if (chart) this.chart.set(chart);
    });
  }
}
