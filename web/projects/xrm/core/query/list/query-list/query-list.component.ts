import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';
import { DialogService } from '@attome/base/dialog';

import { QueryAdminService, QueryMeta } from '@attome/xrm/core/query/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

@Component({
  selector:   'xrm-query-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [OwnerLayerBadgeComponent, FormsModule, RouterLink, TranslatePipe],
  styleUrls:  ['../../../../styles/admin-page.css', '../../query-page.css', './query-list.component.css'],
  templateUrl: './query-list.component.html',
})
export class QueryListComponent implements OnInit {
  private readonly svc      = inject(QueryAdminService);
  private readonly router   = inject(Router);
  private readonly dialogSvc = inject(DialogService);

  readonly queries = signal<QueryMeta[]>([]);
  readonly loading = signal(true);
  readonly error   = signal<string | null>(null);

  search = '';

  readonly filtered = computed(() => {
    const q = this.search.toLowerCase();
    return q === ''
      ? this.queries()
      : this.queries().filter(r =>
          r.name.toLowerCase().includes(q) || r.sql_preview.toLowerCase().includes(q)
        );
  });

  ngOnInit(): void { this.load(); }

  private load(): void {
    this.loading.set(true);
    this.svc.listQueries().subscribe({
      next:  qs => { this.queries.set(qs); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  async deleteQuery(q: QueryMeta): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({
      message: `Are you sure you want to delete "${q.name}"? This cannot be undone.`,
      variant: 'danger',
      confirmText: 'Delete',
    });
    if (!confirmed) return;
    this.svc.deleteQuery(q.id).subscribe({
      next:  () => this.queries.update(list => list.filter(x => x.id !== q.id)),
      error: (e: ApiError) => { void this.dialogSvc.error(e.message); },
    });
  }
}
