import { ChangeDetectionStrategy, Component, OnInit, inject, input, signal } from '@angular/core';
import { DatePipe, JsonPipe } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ApiError, TranslatePipe } from '@attome/base';

import { InstanceDetail, WorkflowAdminService } from '../../../services/workflow-admin.service';

@Component({
  selector:   'attome-workflow-instance-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [RouterLink, DatePipe, JsonPipe, TranslatePipe],
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
  /** M4-T2: the test made from this failed run, once made. */
  readonly madeTest   = signal<string | null>(null);
  readonly makingTest = signal(false);
  readonly testError  = signal<string | null>(null);

  ngOnInit(): void { this.load(); }

  private load(): void {
    this.loading.set(true);
    this.svc.getInstance(this.id()).subscribe({
      next:  i => { this.instance.set(i); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  /** M4-T2: turns this failed run into a customer test in one step. */
  makeTest(): void {
    const inst = this.instance();
    if (!inst) return;
    this.makingTest.set(true);
    this.testError.set(null);
    this.svc.testFromRun(inst.id).subscribe({
      next:  t => { this.makingTest.set(false); this.madeTest.set(t.name); },
      error: (e: ApiError) => { this.testError.set(e.message); this.makingTest.set(false); },
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
