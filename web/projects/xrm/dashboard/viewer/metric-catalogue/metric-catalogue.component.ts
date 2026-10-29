import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { DashboardService, MetricCatalogueItem } from '@attome/xrm/dashboard/data';

/** The metrics whose name or key holds `text`, ignoring case. Pure. */
export function filterMetrics(items: readonly MetricCatalogueItem[], text: string): MetricCatalogueItem[] {
  const q = text.trim().toLowerCase();
  if (!q) return [...items];
  return items.filter(m => m.name.toLowerCase().includes(q) || m.key.toLowerCase().includes(q));
}

/**
 * P9-T15: the metric catalogue, searchable by name or key, with each
 * metric's certification, steward, definition version, review date and how
 * many scorecards show it.
 */
@Component({
  selector: 'attome-metric-catalogue',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './metric-catalogue.component.html',
  styleUrls: ['./metric-catalogue.component.css'],
})
export class MetricCatalogueComponent implements OnInit {
  private readonly svc = inject(DashboardService);

  readonly items = signal<MetricCatalogueItem[]>([]);
  readonly search = signal('');
  readonly loading = signal(true);
  readonly failed = signal(false);
  readonly shown = computed(() => filterMetrics(this.items(), this.search()));

  onSearch(event: Event): void {
    this.search.set((event.target as HTMLInputElement | null)?.value ?? '');
  }

  ngOnInit(): void {
    this.svc.listMetrics().subscribe({
      next: page => {
        this.items.set(page.items);
        this.loading.set(false);
      },
      error: () => {
        this.loading.set(false);
        this.failed.set(true);
      },
    });
  }
}
