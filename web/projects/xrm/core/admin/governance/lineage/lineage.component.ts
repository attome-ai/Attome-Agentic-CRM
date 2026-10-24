import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  LINEAGE_KINDS, LINEAGE_MAX_DEPTH, LineageService,
  type LineageComparison, type LineageDirection, type LineageGraph,
} from '@attome/xrm/core/admin/data';
import { GovernanceNavComponent } from '../nav/governance-nav.component';
import { CleanupListComponent } from './cleanup-list.component';
import { LineageGraphComponent } from './lineage-graph.component';
import { walkTarget } from './lineage-layout';

/**
 * L5-T7 — `/xrm/admin/lineage`: walk the lineage graph from an entity, an
 * attribute or a definition, downstream (what uses it) or upstream (what it
 * uses), to a depth, keeping only some definition kinds, as the graph stood
 * after a given publish; compare two versions (edges added and removed);
 * and the cleanup list. Definitions that read personal data are drawn in
 * red. `?node=<key>` deep-links a walk. Read only: lineage is captured at
 * publish, and documented by hand through the API (L5-T5).
 */
@Component({
  selector: 'xrm-lineage',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, GovernanceNavComponent, LineageGraphComponent, CleanupListComponent],
  styleUrls: ['../../../../styles/admin-page.css', '../governance.css', './lineage.component.css'],
  template: `
    <xrm-governance-nav />
    <div class="page-header">
      <div>
        <h2>{{ 'governance.lineage.title' | translate }}</h2>
        <p class="subtitle">{{ 'governance.lineage.subtitle' | translate }}</p>
      </div>
    </div>

    <form class="gov-filters ln-form" (ngSubmit)="walk()">
      <label>{{ 'governance.lineage.kind' | translate }}
        <select name="kind" data-lineage-kind [ngModel]="kind()" (ngModelChange)="kind.set($event)">
          <option value="entity">{{ 'governance.lineage.kinds.entity' | translate }}</option>
          @for (k of kinds; track k) {
            <option [value]="k">{{ 'governance.lineage.kinds.' + k | translate }}</option>
          }
        </select>
      </label>
      <label>{{ (kind() === 'entity' ? 'governance.lineage.entityRef' : 'governance.lineage.definitionRef') | translate }}
        <input name="ref" class="mono-input" dir="ltr" data-lineage-ref required
               [ngModel]="ref()" (ngModelChange)="ref.set($event)" />
      </label>
      <fieldset class="ln-direction">
        <legend>{{ 'governance.lineage.direction' | translate }}</legend>
        <label><input type="radio" name="direction" value="down" [ngModel]="direction()" (ngModelChange)="direction.set($event)" />
          {{ 'governance.lineage.down' | translate }}</label>
        <label><input type="radio" name="direction" value="up" [ngModel]="direction()" (ngModelChange)="direction.set($event)" />
          {{ 'governance.lineage.up' | translate }}</label>
      </fieldset>
      <label>{{ 'governance.lineage.depth' | translate }}
        <input name="depth" type="number" min="1" [max]="maxDepth" data-lineage-depth
               [ngModel]="depth()" (ngModelChange)="depth.set(+$event)" />
      </label>
      <fieldset class="ln-kinds">
        <legend>{{ 'governance.lineage.keepKinds' | translate }}</legend>
        @for (k of kinds; track k) {
          <label><input type="checkbox" [name]="'k-' + k" [checked]="kept().includes(k)" (change)="toggleKind(k)" />
            {{ 'governance.lineage.kinds.' + k | translate }}</label>
        }
      </fieldset>
      <label>{{ 'governance.lineage.version' | translate }}
        <input name="version" type="number" min="1" data-lineage-version [placeholder]="'governance.lineage.current' | translate"
               [ngModel]="version()" (ngModelChange)="version.set($event === '' || $event === null ? null : +$event)" />
      </label>
      <label>{{ 'governance.lineage.compareWith' | translate }}
        <input name="compareFrom" type="number" min="1" data-lineage-compare
               [ngModel]="compareFrom()" (ngModelChange)="compareFrom.set($event === '' || $event === null ? null : +$event)" />
      </label>
      <button type="submit" class="btn-primary" data-lineage-walk [disabled]="loading() || !ref().trim()">
        {{ 'governance.lineage.walk' | translate }}
      </button>
    </form>
    @if (compareFrom() !== null && version() === null) {
      <p class="hint">{{ 'governance.lineage.compareNeedsVersion' | translate }}</p>
    }

    @if (error(); as e) { <p class="error-msg" role="alert">{{ e }}</p> }

    @if (graph(); as g) {
      <section class="card" aria-labelledby="ln-graph-title">
        <h3 id="ln-graph-title">{{ walked() }}</h3>
        @if (g.hidden > 0) { <p class="hint">{{ 'governance.lineage.hidden' | translate: { count: g.hidden } }}</p> }
        @if (g.truncated) { <p class="hint" role="status">{{ 'governance.lineage.truncated' | translate }}</p> }
        <p class="ln-legend">
          <span class="ln-key ln-key--sensitive"></span> {{ 'governance.lineage.legendPersonal' | translate }}
          @if (comparison()) { <span class="ln-key ln-key--added"></span> {{ 'governance.lineage.legendAdded' | translate }} }
          <span class="ln-key ln-key--guess"></span> {{ 'governance.lineage.legendEntityOnly' | translate }}
        </p>
        <xrm-lineage-graph [graph]="g" [direction]="lastDirection()" [rtl]="lang.isRtl()"
                           [comparison]="comparison()" (open)="openKey($event)" />
      </section>
    }

    @if (comparison(); as c) {
      <section class="card" aria-labelledby="ln-compare-title" data-lineage-comparison>
        <h3 id="ln-compare-title">{{ 'governance.lineage.compareTitle' | translate: { from: c.from, to: c.to } }}</h3>
        <h4>{{ 'governance.lineage.added' | translate }} <span class="count">{{ c.added.length }}</span></h4>
        <ul class="lc-list">
          @for (e of c.added; track e.from + e.to + e.edge_kind) {
            <li class="cell-mono" dir="ltr">{{ e.from }} → {{ e.to }} ({{ e.edge_kind }})</li>
          }
        </ul>
        <h4>{{ 'governance.lineage.removed' | translate }} <span class="count">{{ c.removed.length }}</span></h4>
        <ul class="lc-list">
          @for (e of c.removed; track e.from + e.to + e.edge_kind) {
            <li class="cell-mono lc-gone" dir="ltr">{{ e.from }} → {{ e.to }} ({{ e.edge_kind }})</li>
          }
        </ul>
        @if (c.truncated) { <p class="hint">{{ 'governance.lineage.truncated' | translate }}</p> }
      </section>
    }

    <xrm-lineage-cleanup (open)="openKey($event)" />
  `,
})
export class LineageComponent implements OnInit {
  private readonly svc = inject(LineageService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);
  protected readonly lang = inject(LangService);

  /** Query param `?node=` — a node key to walk from on load. */
  readonly node = input<string | undefined>(undefined);

  readonly kinds = LINEAGE_KINDS;
  readonly maxDepth = LINEAGE_MAX_DEPTH;

  readonly kind = signal('entity');
  readonly ref = signal('');
  readonly direction = signal<LineageDirection>('down');
  readonly depth = signal(3);
  readonly kept = signal<string[]>([]);
  readonly version = signal<number | null>(null);
  readonly compareFrom = signal<number | null>(null);

  readonly graph = signal<LineageGraph | null>(null);
  readonly comparison = signal<LineageComparison | null>(null);
  readonly lastDirection = signal<LineageDirection>('down');
  readonly walked = signal('');
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  ngOnInit(): void {
    const initial = this.node();
    if (initial) this.openKey(initial, false);
  }

  toggleKind(kind: string): void {
    this.kept.update(list => (list.includes(kind) ? list.filter(k => k !== kind) : [...list, kind]));
  }

  /** Walks from a node key (`entity:<e>[.<a>]` or `<kind>:<id>`). */
  openKey(key: string, updateUrl = true): void {
    const target = walkTarget(key);
    if (!target) return;
    this.kind.set(target.kind);
    this.ref.set(target.ref);
    this.walk(updateUrl);
  }

  walk(updateUrl = true): void {
    const kind = this.kind();
    const ref = this.ref().trim();
    if (!ref) return;
    const depth = Math.min(LINEAGE_MAX_DEPTH, Math.max(1, Math.round(this.depth() || 3)));
    this.depth.set(depth);
    this.loading.set(true);
    this.error.set(null);
    const direction = this.direction();
    if (updateUrl) {
      void this.router.navigate([], { queryParams: { node: `${kind}:${ref}` }, queryParamsHandling: 'merge' });
    }
    this.svc.walk(kind, ref, { direction, depth, kinds: this.kept(), version: this.version() })
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: g => {
          this.graph.set(g);
          this.lastDirection.set(direction);
          this.walked.set(`${kind}:${ref}`);
          this.loading.set(false);
        },
        error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
      });
    const from = this.compareFrom();
    const to = this.version();
    if (from !== null && to !== null) {
      this.svc.compare(from, to).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: c => this.comparison.set(c),
        error: (e: ApiError) => this.error.set(e.message),
      });
    } else {
      this.comparison.set(null);
    }
  }
}
