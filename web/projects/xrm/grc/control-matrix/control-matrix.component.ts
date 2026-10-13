import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { forkJoin } from 'rxjs';
import { TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';

interface AxisItem {
  id:    string;
  label: string;
}

/**
 * `grc_control_requirement`'s list-page override (M20-grc.md Phase 1
 * checklist) — a control-to-requirement M:M mapping is not meaningfully
 * browsable as a flat row list (one row per pair tells a reader nothing
 * about coverage), so this renders it as an actual matrix: controls down the
 * rows, requirements across the columns, a mark in every mapped cell.
 *
 * Fetches the three entities it needs directly through `EntityService`
 * (controls/requirements for the axis labels, the mapping rows for which
 * cells are marked) rather than relying on `query/execute`'s per-row
 * `lookups` metadata: `EntityService.list`'s current mapping does not
 * forward that map to the caller (see that method's own doc comment), so
 * resolving `control_id`/`requirement_id` display names needs their owning
 * entities' own rows regardless.
 */
@Component({
  selector: 'attome-grc-control-matrix',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './control-matrix.component.html',
  styleUrl: './control-matrix.component.css',
})
export class ControlMatrixComponent {
  private readonly entityService = inject(EntityService);

  protected readonly controls = signal<AxisItem[]>([]);
  protected readonly requirements = signal<AxisItem[]>([]);
  /** Set of `"{controlId}|{requirementId}"` pairs that are mapped. */
  private readonly mappedPairs = signal<ReadonlySet<string>>(new Set());
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);

  protected readonly coveragePercent = computed(() => {
    const total = this.controls().length * this.requirements().length;
    if (total === 0) return 0;
    return Math.round((this.mappedPairs().size / total) * 100);
  });

  constructor() {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    forkJoin({
      controls: this.entityService.list('grc_control', { limit: 200, offset: 0 }),
      requirements: this.entityService.list('grc_requirement', { limit: 200, offset: 0 }),
      mappings: this.entityService.list('grc_control_requirement', { limit: 1000, offset: 0 }),
    }).subscribe({
      next: ({ controls, requirements, mappings }) => {
        this.controls.set(
          controls.data.map(r => ({ id: r.id, label: String(r.data['name'] ?? r.id) })),
        );
        this.requirements.set(
          requirements.data.map(r => ({ id: r.id, label: String(r.data['clause'] ?? r.id) })),
        );
        const pairs = new Set<string>();
        for (const row of mappings.data) {
          const controlId = String(row.data['control_id'] ?? '');
          const requirementId = String(row.data['requirement_id'] ?? '');
          if (controlId && requirementId) pairs.add(`${controlId}|${requirementId}`);
        }
        this.mappedPairs.set(pairs);
        this.loading.set(false);
      },
      error: () => {
        this.error.set('grc.controlMatrix.loadError');
        this.loading.set(false);
      },
    });
  }

  protected isMapped(controlId: string, requirementId: string): boolean {
    return this.mappedPairs().has(`${controlId}|${requirementId}`);
  }
}
