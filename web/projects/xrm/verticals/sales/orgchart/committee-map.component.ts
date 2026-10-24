import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { entityFormRoute } from '@attome/xrm/core/entity';
import { catchError, of } from 'rxjs';

import { CARD_H, CARD_W, ChartLayout, layoutChart } from './org-chart.component';
import { CoverageGap, DealContact, DealMap, InfluenceLink, OrgChartService, OrgNode } from './orgchart.service';

/** An "influences" line where the layout put both cards. */
export interface InfluenceLine {
  from: string;
  to: string;
  path: string;
}

/**
 * The cards to lay out: the account's chart when the API sent one, else the
 * deal's contacts side by side. A deal contact missing from the chart is
 * added as its own root, so everyone on the committee has a card. Pure.
 */
export function committeeRoots(map: DealMap): OrgNode[] {
  const roots = [...(map.chart?.roots ?? [])];
  const onChart = new Set<string>();
  const walk = (n: OrgNode) => { onChart.add(n.id); n.children.forEach(walk); };
  roots.forEach(walk);
  for (const c of map.contacts) {
    if (onChart.has(c.contact_id)) continue;
    onChart.add(c.contact_id);
    roots.push({
      id: c.contact_id, full_name: c.full_name, is_former_employee: false, children: [],
    });
  }
  return roots;
}

/** Dashed curves from one card's centre to another's, bowing away from the tree. Pure. */
export function influenceLines(layout: ChartLayout, links: readonly InfluenceLink[]): InfluenceLine[] {
  const at = new Map(layout.cards.map(c => [c.node.id, c]));
  const lines: InfluenceLine[] = [];
  for (const l of links) {
    const a = at.get(l.from_contact);
    const b = at.get(l.to_contact);
    if (!a || !b) continue;
    const x1 = a.x + CARD_W / 2;
    const y1 = a.y + CARD_H / 2;
    const x2 = b.x + CARD_W / 2;
    const y2 = b.y + CARD_H / 2;
    const bow = Math.max(24, Math.abs(x2 - x1) / 4);
    const cx = (x1 + x2) / 2;
    const cy = Math.min(y1, y2) - bow;
    lines.push({ from: l.from_contact, to: l.to_contact, path: `M${x1},${y1} Q${cx},${cy} ${x2},${y2}` });
  }
  return lines;
}

/**
 * The buying-committee map on an opportunity (roadmap D23-T12): the
 * account's chart with each deal contact's role, influence and attitude as
 * badges, the "influences" links as dashed curves, and the coverage gaps
 * with an action each. Dragging a card's handle onto another card records
 * that the first influences the second (a `record_relationship` row through
 * the generic API). Influence and attitude come only through the Deal
 * Attitude field profile: the API leaves them out for anyone else and this
 * shows nothing in their place. O7 relationship strength shows only when the
 * API returns it.
 */
@Component({
  selector: 'xrm-sales-committee-map',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  template: `
    <section class="cm" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="cm-title" data-testid="cm">
      <h2 id="cm-title">{{ 'salesCommittee.title' | translate }}</h2>
      @if (error(); as message) { <p class="cm-error" role="alert">{{ message }}</p> }
      @if (linked()) { <p class="cm-note" role="status">{{ 'salesCommittee.linked' | translate }}</p> }

      <div class="cm-body">
        <div class="cm-canvas">
          <!-- The layout mirrors x itself, so the drawing plane is always left to right. -->
          <div class="cm-plane" dir="ltr" [style.--cm-w]="layout().width + 'px'" [style.--cm-h]="layout().height + 'px'">
            <svg class="cm-lines" [attr.viewBox]="'0 0 ' + layout().width + ' ' + layout().height" aria-hidden="true">
              @for (l of layout().connectors; track l.from + l.to) { <path class="cm-tree" [attr.d]="l.path" /> }
              @for (l of lines(); track l.from + l.to) { <path class="cm-influence" data-testid="cm-influence" [attr.d]="l.path" /> }
            </svg>
            @for (c of layout().cards; track c.node.id) {
              <article class="cm-card" data-testid="cm-card" [attr.data-id]="c.node.id"
                       [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'"
                       [class.cm-member]="!!member(c.node.id)" [class.cm-former]="c.node.is_former_employee"
                       [style.--cm-x]="c.x + 'px'" [style.--cm-y]="c.y + 'px'"
                       (dragover)="$event.preventDefault()" (drop)="dropOn($event, c.node.id)">
                <strong>{{ c.node.full_name }}</strong>
                @if (member(c.node.id); as m) {
                  <span class="cm-badges">
                    @if (m.role) { <span class="cm-badge" data-testid="cm-role">{{ label('roles', m.role) }}</span> }
                    @if (m.influence) {
                      <span class="cm-badge" data-testid="cm-influence-badge">{{ 'salesCommittee.influence' | translate }}: {{ label('influences', m.influence) }}</span>
                    }
                    @if (m.attitude) {
                      <span class="cm-badge" [class]="'cm-badge cm-attitude-' + m.attitude" data-testid="cm-attitude">{{ label('attitudes', m.attitude) }}</span>
                    }
                    @if (m.strength !== null && m.strength !== undefined) {
                      <span class="cm-badge" data-testid="cm-strength">{{ 'salesCommittee.strength' | translate }} <span dir="ltr">{{ m.strength }}</span></span>
                    }
                  </span>
                  <button type="button" class="cm-handle" draggable="true" data-testid="cm-handle"
                          [attr.aria-label]="'salesCommittee.linkFrom' | translate"
                          (dragstart)="dragStart(c.node.id)">⋮</button>
                }
              </article>
            }
          </div>
        </div>

        <aside class="cm-gaps" aria-labelledby="cm-gaps-title">
          <h3 id="cm-gaps-title">{{ 'salesCommittee.gaps' | translate }}</h3>
          @if (gaps().length === 0) {
            <p data-testid="cm-no-gaps">{{ 'salesCommittee.noGaps' | translate }}</p>
          } @else {
            <ul data-testid="cm-gap-list">
              @for (g of gaps(); track gapKey(g)) {
                <li data-testid="cm-gap">
                  @if (g.kind === 'missing_role') {
                    <span>{{ 'salesCommittee.missingRole' | translate }}: <strong>{{ label('roles', g.role ?? '') }}</strong></span>
                    <a [routerLink]="newRole" [queryParams]="{ opportunity_ref: id(), role: g.role }"
                       data-testid="cm-add-role">{{ 'salesCommittee.addRole' | translate }}</a>
                  } @else {
                    <span>{{ 'salesCommittee.unmet' | translate }}: <strong>{{ nameOf(g.contact_id) }}</strong></span>
                  }
                </li>
              }
            </ul>
          }
        </aside>
      </div>
    </section>
  `,
  styles: [`
    .cm { display: grid; gap: var(--space-3, .75rem); }
    .cm-body { display: grid; grid-template-columns: minmax(0, 1fr) minmax(14rem, 18rem); gap: var(--space-3, .75rem); }
    @media (max-width: 48rem) { .cm-body { grid-template-columns: minmax(0, 1fr); } }
    .cm-canvas { overflow: auto; border: 1px solid var(--color-border, #ddd); border-radius: 6px; padding: var(--space-3, .75rem); }
    .cm-plane { position: relative; inline-size: var(--cm-w); block-size: var(--cm-h); }
    .cm-lines { position: absolute; inset-block-start: 0; inset-inline-start: 0; inline-size: var(--cm-w);
                block-size: var(--cm-h); overflow: visible; }
    .cm-lines path { fill: none; stroke-width: 1.5; }
    .cm-tree { stroke: var(--color-border, #bbb); }
    .cm-influence { stroke: var(--color-primary, #2b6cb0); stroke-dasharray: 6 4; }
    .cm-card { position: absolute; inset-block-start: var(--cm-y); inset-inline-start: var(--cm-x);
               inline-size: 180px; min-block-size: 72px; box-sizing: border-box; padding: .375rem .5rem;
               padding-inline-end: 1.5rem; display: grid; gap: 2px; font-size: .8125rem; align-content: start;
               background: var(--color-bg, #fff); border: 1px solid var(--color-border, #ccc); border-radius: 6px; }
    .cm-card.cm-member { border-color: var(--color-primary, #2b6cb0); }
    .cm-card.cm-former { opacity: .55; }
    .cm-badges { display: flex; flex-wrap: wrap; gap: 2px; }
    .cm-badge { font-size: .6875rem; padding: 0 .375rem; border-radius: 999px; background: var(--color-bg-alt, #f0f0f0); }
    .cm-attitude-champion, .cm-attitude-supporter { background: var(--color-success-bg, #e6f4ea); }
    .cm-attitude-sceptic, .cm-attitude-blocker { background: var(--color-danger-bg, #fde8e8); }
    .cm-handle { position: absolute; inset-block-start: .25rem; inset-inline-end: .25rem; cursor: grab;
                 border: none; background: none; padding: 0 .25rem; }
    .cm-gaps ul { margin: 0; padding-inline-start: 1rem; display: grid; gap: .5rem; }
    .cm-gaps li { display: grid; gap: 2px; }
    .cm-error { color: var(--color-danger, #c53030); }
  `],
})
export class CommitteeMapComponent {
  private readonly service = inject(OrgChartService);
  protected readonly lang = inject(LangService);
  protected readonly newRole = entityFormRoute('opportunity_contact_role');

  /** The opportunity (route parameter or host input). */
  readonly id = input.required<string>();

  protected readonly map = signal<DealMap | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly linked = signal(false);
  private dragged: string | null = null;

  private readonly members = computed(
    () => new Map((this.map()?.contacts ?? []).map(c => [c.contact_id, c])),
  );
  protected readonly layout = computed(() => {
    const map = this.map();
    return layoutChart(map ? committeeRoots(map) : [], this.lang.isRtl());
  });
  protected readonly lines = computed(() => influenceLines(this.layout(), this.map()?.influences ?? []));
  protected readonly gaps = computed(() => this.map()?.gaps ?? []);

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => this.load(id));
    });
  }

  protected member(contact: string): DealContact | undefined {
    return this.members().get(contact);
  }

  protected nameOf(contact: string | null | undefined): string {
    return (contact && this.members().get(contact)?.full_name) || contact || '';
  }

  /** An option code's label (`roles`, `influences`, `attitudes`), falling
   * back to the code for one the catalog lacks. */
  protected label(group: string, code: string): string {
    const key = `salesCommittee.${group}.${code}`;
    const label = this.lang.translate(key);
    return label === key ? code : label;
  }

  protected gapKey(g: CoverageGap): string {
    return `${g.kind}:${g.role ?? ''}:${g.contact_id ?? ''}`;
  }

  protected dragStart(contact: string): void {
    this.dragged = contact;
  }

  protected dropOn(event: Event, target: string): void {
    event.preventDefault();
    const from = this.dragged;
    this.dragged = null;
    if (!from || from === target || !this.member(target)) return;
    const known = (this.map()?.influences ?? []).some(l => l.from_contact === from && l.to_contact === target);
    if (known) return;
    this.error.set(null);
    this.linked.set(false);
    this.service.addInfluence(from, target).pipe(
      catchError((e: unknown) => {
        this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(answer => {
      if (answer === null) return;
      this.linked.set(true);
      this.load(this.id());
    });
  }

  private load(id: string): void {
    this.service.committeeMap(id).pipe(
      catchError((e: unknown) => {
        this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    ).subscribe(map => {
      if (map) this.map.set(map);
    });
  }
}
