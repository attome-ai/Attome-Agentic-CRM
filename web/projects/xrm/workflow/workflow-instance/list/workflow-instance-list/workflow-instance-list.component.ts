import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';

import { InstanceListItem, WorkflowAdminService } from '../../../services/workflow-admin.service';

const STATUSES = ['running', 'waiting', 'completed', 'failed', 'cancelled'];

@Component({
  selector:   'attome-workflow-instance-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [FormsModule, RouterLink, DatePipe],
  styleUrls:  ['../../../../styles/admin-page.css', './workflow-instance-list.component.css'],
  templateUrl: './workflow-instance-list.component.html',
})
export class WorkflowInstanceListComponent implements OnInit {
  private readonly svc = inject(WorkflowAdminService);

  readonly statuses = STATUSES;
  readonly instances = signal<InstanceListItem[]>([]);
  readonly loading   = signal(true);
  readonly error     = signal<string | null>(null);
  readonly statusFilter = signal('');

  readonly filtered = computed(() => this.instances());

  ngOnInit(): void { this.load(); }

  setStatus(s: string): void { this.statusFilter.set(s); this.load(); }

  private load(): void {
    this.loading.set(true);
    this.svc.listInstances(this.statusFilter() || undefined).subscribe({
      next:  is => { this.instances.set(is); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }
}
