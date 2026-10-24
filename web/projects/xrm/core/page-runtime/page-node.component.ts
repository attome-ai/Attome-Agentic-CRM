import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { Router } from '@angular/router';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { DashboardChartComponent, SLICE_COLORS } from '@attome/xrm/dashboard/chart';
import type { ChartCategory, ChartSeries } from '@attome/xrm/dashboard/chart';
import { Observable } from 'rxjs';

import { PageContext } from './page-context';
import { PageDataService, PageRows } from './page-data.service';
import { PageEvent, PageNode, fillTarget, isVisible, seriesOf, textProp } from './page-model';

/** Components that read rows from a view or stored query. */
const ROW_TYPES = new Set(['list', 'chart', 'metric', 'kanban', 'map', 'timeline']);

/**
 * T2-T2: one component of a page, and its children. It shows only when its
 * visibility holds. A component that reads data loads it itself and, if
 * that fails, says so in its own box: one broken component never takes the
 * page down. Kanban, map and timeline show their rows as a list until
 * their own renderers exist; a custom component shows its id (the T3
 * component host renders it).
 */
@Component({
  selector: 'xrm-page-node',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, DashboardChartComponent],
  template: `
    @if (visible()) {
      @switch (node().type) {
        @case ('container') {
          <div class="pn-container" [attr.data-node]="node().id">
            @for (child of children(); track child.id) { <xrm-page-node [node]="child" /> }
          </div>
        }
        @case ('tabs') {
          <div class="pn-tabs" [attr.data-node]="node().id">
            <div role="tablist" class="pn-tablist">
              @for (child of children(); track child.id; let i = $index) {
                <button type="button" role="tab" [attr.aria-selected]="tab() === i" (click)="tab.set(i)">
                  {{ titleOf(child) || child.id }}
                </button>
              }
            </div>
            @if (children()[tab()]; as current) { <div role="tabpanel"><xrm-page-node [node]="current" /></div> }
          </div>
        }
        @case ('text') {
          <p class="pn-text" [attr.data-node]="node().id" dir="auto">{{ text('text') }}</p>
        }
        @case ('button') {
          <button type="button" class="pn-button" [attr.data-node]="node().id" [disabled]="busy()" (click)="fire('click')">
            {{ text('label') || ('pageRuntime.run' | translate) }}
          </button>
          @if (error()) { <p class="pn-error" role="alert">{{ 'pageRuntime.actionFailed' | translate }}</p> }
        }
        @case ('form') {
          <section class="pn-box" [attr.data-node]="node().id">
            @if (title(); as t) { <h3>{{ t }}</h3> }
            @if (ctx.record(); as values) {
              <dl class="pn-fields">
                @for (f of formFields(); track f.name) {
                  <dt>{{ f.label }}</dt><dd dir="auto">{{ show(values[f.name]) }}</dd>
                }
              </dl>
            } @else {
              <p class="pn-muted">{{ 'pageRuntime.noRecord' | translate }}</p>
            }
          </section>
        }
        @case ('custom') {
          <section class="pn-box pn-custom" [attr.data-node]="node().id">
            <p class="pn-muted">{{ 'pageRuntime.custom' | translate: { id: node().component || '' } }}</p>
          </section>
        }
        @default {
          <section class="pn-box" [attr.data-node]="node().id">
            @if (title(); as t) { <h3>{{ t }}</h3> }
            @if (error()) {
              <p class="pn-error" role="alert" data-node-error>{{ 'pageRuntime.failed' | translate }}</p>
            } @else if (rows() === null) {
              <p class="pn-muted">{{ 'pageRuntime.loading' | translate }}</p>
            } @else if (node().type === 'metric') {
              <p class="pn-metric" data-metric>{{ metric() }}</p>
            } @else if (node().type === 'chart' && categories().length) {
              <attome-dashboard-chart kind="bar" [title]="title()" [categories]="categories()" [series]="series()" />
            } @else {
              @if (node().type !== 'list' && node().type !== 'chart') {
                <p class="pn-muted">{{ 'pageRuntime.asList' | translate }}</p>
              }
              @if (columns().length) {
                <div class="pn-table-wrap">
                  <table class="pn-table">
                    <thead><tr>@for (c of columns(); track c) { <th scope="col">{{ c }}</th> }</tr></thead>
                    <tbody>
                      @for (r of rows()!.records; track $index) {
                        <tr [class.pn-clickable]="selectable()" (click)="select(r)" (keydown.enter)="select(r)" [attr.tabindex]="selectable() ? 0 : null">
                          @for (c of columns(); track c) { <td dir="auto">{{ show(r[c]) }}</td> }
                        </tr>
                      }
                    </tbody>
                  </table>
                </div>
              } @else {
                <p class="pn-muted">{{ 'pageRuntime.empty' | translate }}</p>
              }
            }
          </section>
        }
      }
    }
  `,
  styles: [`
    :host { display: block; }
    .pn-container { display: grid; gap: var(--space-3, .75rem); }
    .pn-tablist { display: flex; flex-wrap: wrap; gap: .25rem; border-block-end: 1px solid var(--color-border, #ddd); margin-block-end: .5rem; }
    .pn-tablist [aria-selected='true'] { font-weight: 700; }
    .pn-box { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; min-inline-size: 0; }
    .pn-box h3 { margin: 0 0 .5rem; font-size: 1rem; }
    .pn-muted { color: var(--color-text-secondary, #666); margin: 0; }
    .pn-error { color: var(--color-danger, #c53030); margin: 0; }
    .pn-metric { font-size: 2rem; font-weight: 700; margin: 0; }
    .pn-table-wrap { overflow-x: auto; }
    .pn-table { inline-size: 100%; border-collapse: collapse; font-size: .875rem; }
    .pn-table th, .pn-table td { text-align: start; padding: .25rem .5rem; border-block-end: 1px solid var(--color-border, #eee); }
    .pn-clickable { cursor: pointer; }
    .pn-fields { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: .25rem .75rem; margin: 0; }
    .pn-fields dt { color: var(--color-text-secondary, #666); }
    .pn-fields dd { margin: 0; }
  `],
})
export class PageNodeComponent {
  protected readonly ctx = inject(PageContext);
  private readonly data = inject(PageDataService);
  private readonly router = inject(Router);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly node = input.required<PageNode>();

  protected readonly tab = signal(0);
  protected readonly rows = signal<PageRows | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);

  protected readonly visible = computed(() => {
    try {
      return isVisible(this.node(), this.ctx.visibility());
    } catch {
      return false;
    }
  });
  protected readonly children = computed(() => this.node().children ?? []);
  protected readonly title = computed(() => this.titleOf(this.node()));
  protected readonly columns = computed(() => {
    const first = this.rows()?.records[0];
    return first ? Object.keys(first).filter(k => k !== 'id' && !k.endsWith('_ref')).slice(0, 8) : [];
  });
  protected readonly selectable = computed(() => (this.node().events ?? []).some(e => e.on === 'select'));
  protected readonly metric = computed(() => {
    const first = seriesOf(this.rows()?.records ?? [])[0];
    if (first) return first.value.toLocaleString(this.lang.intlLocale());
    return String(this.rows()?.total ?? 0);
  });
  protected readonly categories = computed<ChartCategory[]>(() =>
    seriesOf(this.rows()?.records ?? []).map((p, i) => ({ trackKey: `${i}`, label: p.label })));
  protected readonly series = computed<ChartSeries[]>(() => [{
    trackKey: 'value', name: this.title(), color: SLICE_COLORS[0],
    points: seriesOf(this.rows()?.records ?? []).map((p, i) => ({ trackKey: `${i}`, label: p.label, value: p.value, key: null })),
  }]);
  protected readonly formFields = computed(() => {
    const wanted = this.node().props?.['fields'];
    const fields = this.ctx.schema()?.fields ?? [];
    const names = Array.isArray(wanted) ? wanted.map(String) : fields.slice(0, 12).map(f => f.name);
    return names.map(name => ({ name, label: fields.find(f => f.name === name)?.display_name ?? name }));
  });

  constructor() {
    effect(() => {
      const node = this.node();
      const visible = this.visible();
      untracked(() => {
        if (visible && ROW_TYPES.has(node.type) && node.binding) this.load(node);
        if (visible) for (const e of node.events ?? []) if (e.on === 'load') this.run(e, this.ctx.recordId());
      });
    });
  }

  protected titleOf(node: PageNode): string {
    return textProp(node.props, 'title', this.ctx.arabic());
  }

  protected text(key: string): string {
    return textProp(this.node().props, key, this.ctx.arabic());
  }

  protected show(value: unknown): string {
    if (value === null || value === undefined) return '';
    return typeof value === 'object' ? JSON.stringify(value) : String(value);
  }

  protected fire(on: PageEvent['on']): void {
    for (const e of this.node().events ?? []) if (e.on === on) this.run(e, this.ctx.recordId());
  }

  protected select(row: Record<string, unknown>): void {
    const id = row['id'] === undefined || row['id'] === null ? null : String(row['id']);
    for (const e of this.node().events ?? []) if (e.on === 'select') this.run(e, id);
  }

  private run(event: PageEvent, id: string | null): void {
    if (event.do === 'navigate') {
      const url = fillTarget(event.target, id);
      if (url) void this.router.navigateByUrl(url);
      return;
    }
    const entity = this.ctx.entity();
    const call: Observable<unknown> = event.do === 'start_flow'
      ? this.data.startFlow(event.target, entity, id)
      : this.data.runAction(event.target, entity, id);
    this.busy.set(true);
    call.subscribe({
      next: () => this.busy.set(false),
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }

  private load(node: PageNode): void {
    this.rows.set(null);
    this.error.set(null);
    const sub = this.data.rows(node.binding!).subscribe({
      next: rows => this.rows.set(rows),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
    this.destroyRef.onDestroy(() => sub.unsubscribe());
  }
}
