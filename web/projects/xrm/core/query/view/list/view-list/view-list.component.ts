import { ChangeDetectionStrategy, Component, inject, OnInit, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { ViewAdminService, ViewDetail } from '@attome/xrm/core/query/data';
import { OwnerLayerBadgeComponent } from '@attome/xrm/core/generic/components';

@Component({
  selector: 'xrm-view-list', standalone: true, imports: [OwnerLayerBadgeComponent, RouterLink],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../../../../styles/admin-page.css', '../../../query-page.css', './view-list.component.css'],
  templateUrl: './view-list.component.html',
})
export class ViewListComponent implements OnInit {
  private readonly api = inject(ViewAdminService);
  private readonly dialogSvc = inject(DialogService);
  readonly views = signal<ViewDetail[]>([]); readonly loading = signal(true); readonly error = signal('');
  ngOnInit(): void { this.reload(); }
  private reload(): void { this.api.list().subscribe({ next: v => { this.views.set(v); this.loading.set(false); }, error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); } }); }
  async remove(v: ViewDetail): Promise<void> {
    const confirmed = await this.dialogSvc.confirm({ message: `Delete view "${v.name}"?`, variant: 'danger', confirmText: 'Delete' });
    if (!confirmed) return;
    this.api.delete(v.id).subscribe({ next: () => this.reload(), error: (e: ApiError) => { void this.dialogSvc.error(e.message); } });
  }
}
