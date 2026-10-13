import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { DatePipe, JsonPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';

import { InstanceDetail, WorkflowAdminService } from '../../../services/workflow-admin.service';

@Component({
  selector:   'attome-workflow-instance-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [RouterLink, DatePipe, JsonPipe],
  styleUrls:  ['../../../../styles/admin-page.css', './workflow-instance-detail.component.css'],
  templateUrl: './workflow-instance-detail.component.html',
})
export class WorkflowInstanceDetailComponent implements OnInit {
  private readonly svc = inject(WorkflowAdminService);

  readonly id = input.required<string>();

  readonly instance   = signal<InstanceDetail | null>(null);
  readonly loading    = signal(true);
  readonly error      = signal<string | null>(null);
  readonly cancelling = signal(false);
  readonly cancelError = signal<string | null>(null);

  ngOnInit(): void { this.load(); }

  private load(): void {
    this.loading.set(true);
    this.svc.getInstance(this.id()).subscribe({
      next:  i => { this.instance.set(i); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  cancel(): void {
    const inst = this.instance();
    if (!inst) return;
    this.cancelling.set(true);
    this.cancelError.set(null);
    this.svc.cancelInstance(inst.id, inst.row_version).subscribe({
      next:  () => { this.cancelling.set(false); this.load(); },
      error: (e: ApiError) => { this.cancelError.set(e.message); this.cancelling.set(false); },
    });
  }
}
