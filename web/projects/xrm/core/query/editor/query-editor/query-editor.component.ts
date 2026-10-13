import { ChangeDetectionStrategy, Component, inject, input, OnInit, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';
import { QueryAdminService, QueryDetail } from '@attome/xrm/core/query/data';
import { QueryService } from '@attome/xrm/core/query/data';
import { QueryExecResponse } from '@attome/xrm/core/query/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

@Component({
  selector: 'xrm-query-editor', standalone: true, imports: [OwnerLayerBadgeComponent, FormsModule, RouterLink, TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../../../styles/xrm-form.css', '../../query-page.css', './query-editor.component.css'],
  templateUrl: './query-editor.component.html',
})
export class QueryEditorComponent implements OnInit {
  private readonly api = inject(QueryAdminService); private readonly queryApi = inject(QueryService); private readonly router = inject(Router);
  readonly id = input.required<string>(); get isNew(): boolean { return !this.id() || this.id() === 'new'; }
  readonly loading = signal(true); readonly loadError = signal(''); readonly saving = signal(false); readonly saveError = signal('');
  readonly testing = signal(false); readonly testError = signal(''); readonly testResult = signal<QueryExecResponse | null>(null); readonly queryName = signal('New Query');
  /** Solution 7 (D-785): the loaded query's owner layer, for the read-only badge. */
  readonly ownerLayer = signal<string | null>(null);
  editName = ''; editSql = ''; editRequiredPrivilege = ''; editIsReport = false;
  ngOnInit(): void { if (this.isNew) { this.loading.set(false); return; } this.api.getQuery(this.id()).subscribe({ next: q => { this.apply(q); this.loading.set(false); }, error: (e: ApiError) => { this.loadError.set(e.message); this.loading.set(false); } }); }
  private apply(q: QueryDetail): void { this.ownerLayer.set(q.owner_layer ?? null); this.queryName.set(q.name); this.editName = q.name; this.editSql = q.sql_query; this.editRequiredPrivilege = q.required_privilege ?? ''; this.editIsReport = q.is_report; }
  save(): void {
    const sql = this.editSql.trim(); if (!sql) { this.saveError.set('SQL statement is required.'); return; }
    const body = { name: this.editName.trim() || undefined, sql_query: sql, required_privilege: this.editRequiredPrivilege.trim() || undefined, is_report: this.editIsReport };
    this.saving.set(true); const request = this.isNew ? this.api.createQuery(body) : this.api.updateQuery(this.id(), body);
    request.subscribe({ next: q => { this.saving.set(false); this.apply(q); if (this.isNew) void this.router.navigate(['/xrm/admin/queries', q.id]); }, error: (e: ApiError) => { this.saveError.set(e.message); this.saving.set(false); } });
  }
  runTest(): void { this.testing.set(true); this.testError.set(''); this.queryApi.execute({ query_id: this.id(), page: 1, page_size: 10, include_total: true }).subscribe({ next: r => { this.testResult.set(r); this.testing.set(false); }, error: (e: ApiError) => { this.testError.set(e.message); this.testing.set(false); } }); }
  cancel(): void { void this.router.navigate(['/xrm/admin/queries']); }
}
