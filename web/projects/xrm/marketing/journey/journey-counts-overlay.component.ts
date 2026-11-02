import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { LangService, TranslatePipe } from '@attome/base';

import { JourneyCounts, JourneyNodeCount, JourneyService } from './journey.service';

/** A node as the overlay places it: its id and canvas position. */
export interface OverlayNode {
  id: string;
  ports?: { x?: number; y?: number } | null;
}

/** How often the counts are read again. */
export const COUNTS_POLL_MS = 10_000;

/** The counts of `version`, else of the newest version with any. Pure. */
export function countsFor(counts: JourneyCounts | null, version: string | null): Map<string, JourneyNodeCount> {
  const nodes = counts?.nodes ?? [];
  const own = nodes.filter(n => n.definition_version_id === version);
  const latest = nodes.at(-1)?.definition_version_id;
  const chosen = own.length > 0 ? own : nodes.filter(n => n.definition_version_id === latest);
  return new Map(chosen.map(n => [n.node_id, n]));
}

/**
 * The journey's live counts drawn on the workflow editor's canvas (roadmap
 * E8-T13): above each node, how many people entered, wait there, were
 * blocked and left, read again every ten seconds. It sits in the canvas'
 * own coordinates, so it moves and pans with the graph; numbers stay left
 * to right in Arabic. The node `highlight` names (a replayed person's
 * current step) is outlined.
 */
@Component({
  selector: 'xrm-journey-counts-overlay',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DecimalPipe, TranslatePipe],
  template: `
    @for (n of placed(); track n.id) {
      <div class="jc" [style.left.px]="n.x" [style.top.px]="n.y" [class.jc-on]="n.id === highlight()"
           [style.transform]="lang.isRtl() ? 'scaleX(-1)' : null"
           [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="jc">
        <span [title]="'journeyEditor.entered' | translate" dir="ltr">{{ n.count.entered | number }}</span>
        <span [title]="'journeyEditor.waiting' | translate" dir="ltr" class="jc-wait">{{ n.count.waiting | number }}</span>
        @if (n.count.blocked > 0) {
          <span [title]="'journeyEditor.blocked' | translate" dir="ltr" class="jc-block">{{ n.count.blocked | number }}</span>
        }
        @if (n.count.exited > 0) {
          <span [title]="'journeyEditor.left' | translate" dir="ltr" class="jc-left">{{ n.count.exited | number }}</span>
        }
      </div>
    }
    @if (failed()) {
      <p class="jc-failed" role="status">{{ 'journeyEditor.countsFailed' | translate }}</p>
    }
  `,
  styles: [`
    :host { position: absolute; inset: 0; pointer-events: none; }
    .jc {
      position: absolute; display: flex; gap: 4px; padding-block: 1px; padding-inline: 6px;
      border-radius: 10px; font-size: 11px; background: var(--color-bg-alt);
      border: 1px solid var(--color-border); color: var(--color-text-primary);
    }
    .jc-on { border-color: var(--color-accent); box-shadow: 0 0 0 2px var(--color-accent); }
    .jc-wait { color: var(--color-accent); }
    .jc-block { color: var(--color-warning); }
    .jc-left { color: var(--color-text-secondary); }
    .jc-failed { position: absolute; inset-block-start: 4px; inset-inline-start: 4px; font-size: 11px; }
  `],
})
export class JourneyCountsOverlayComponent {
  protected readonly lang = inject(LangService);
  private readonly journeys = inject(JourneyService);

  /** The marketing journey record. */
  readonly journeyId = input.required<string>();
  /** The version on the canvas. */
  readonly versionId = input<string | null>(null);
  /** The canvas' nodes, with their positions. */
  readonly nodes = input<readonly OverlayNode[]>([]);
  /** A node to outline. */
  readonly highlight = input<string | null>(null);

  readonly counts = signal<JourneyCounts | null>(null);
  readonly failed = signal(false);

  readonly placed = computed(() => {
    const byNode = countsFor(this.counts(), this.versionId());
    return this.nodes().flatMap(n => {
      const count = byNode.get(n.id);
      if (!count) return [];
      return [{ id: n.id, x: n.ports?.x ?? 0, y: Math.max(0, (n.ports?.y ?? 0) - 22), count }];
    });
  });

  constructor() {
    effect(onCleanup => {
      const journey = this.journeyId();
      const load = () => this.journeys.counts(journey).subscribe({
        next: c => { this.counts.set(c); this.failed.set(false); },
        error: () => this.failed.set(true),
      });
      load();
      const timer = setInterval(load, COUNTS_POLL_MS);
      onCleanup(() => clearInterval(timer));
    });
  }
}
