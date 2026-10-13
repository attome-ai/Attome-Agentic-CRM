import { ChangeDetectionStrategy, Component, OnChanges, inject, input, signal } from '@angular/core';
import { ApiError } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityService, RelatedGridComponent } from '@attome/xrm/core/entity';
import { ChangeRequestDecisionResponse, ProjectService } from '../../services/project.service';

const ENTITY = 'project_change_request';

/**
 * The Change Requests tab — a "Pending Decisions" panel (Approve/Reject
 * against `POST /project/change-request/{id}/approve|reject`,
 * `crates/engine/attome-project/src/change_request.rs`) above the existing generic
 * grid, which stays for browsing/editing every change request (decided or
 * not) and creating new ones. Only `status = 'pending'` rows for this
 * project are fetched for the decision panel — a decided request has
 * nothing left to decide and belongs in the grid below instead.
 */
@Component({
  selector: 'attome-project-change-requests-tab',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RelatedGridComponent],
  styleUrls: ['./project-change-requests-tab.component.css'],
  templateUrl: './project-change-requests-tab.component.html',
})
export class ProjectChangeRequestsTabComponent implements OnChanges {
  private readonly entitySvc = inject(EntityService);
  private readonly projectSvc = inject(ProjectService);

  readonly ENTITY = ENTITY;
  readonly projectId = input.required<string>();

  readonly pending = signal<EntityRecord[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);

  /** id of the change request whose Approve/Reject is in flight, if any —
   *  disables just that row's buttons rather than the whole panel. */
  readonly decidingId = signal<string | null>(null);
  readonly decisionNote = signal<string | null>(null);

  ngOnChanges(): void { this.load(); }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.entitySvc
      .list(ENTITY, {
        filters: [
          { field: 'project_id', op: 'eq', value: this.projectId() },
          { field: 'status', op: 'eq', value: 'pending' },
        ],
        sorts: [{ field: 'requested_date', dir: 'desc' }],
        limit: 100,
      })
      .subscribe({
        next: res => { this.pending.set(res.data); this.loading.set(false); },
        error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
      });
  }

  title(r: EntityRecord): string {
    return String(r.data['title'] ?? '(untitled)');
  }

  impactBudget(r: EntityRecord): number | null {
    const v = r.data['impact_budget'];
    return v == null ? null : Number(v);
  }

  impactScheduleDays(r: EntityRecord): number | null {
    const v = r.data['impact_schedule_days'];
    return v == null ? null : Number(v);
  }

  isCustomerFacing(r: EntityRecord): boolean {
    return r.data['is_customer_facing'] === true;
  }

  approve(r: EntityRecord): void { this.decide(r, this.projectSvc.approveChangeRequest(r.id)); }
  reject(r: EntityRecord): void { this.decide(r, this.projectSvc.rejectChangeRequest(r.id)); }

  private decide(r: EntityRecord, call: ReturnType<ProjectService['approveChangeRequest']>): void {
    this.decidingId.set(r.id);
    this.decisionNote.set(null);
    call.subscribe({
      next: (res: ChangeRequestDecisionResponse) => {
        this.decidingId.set(null);
        this.decisionNote.set(
          res.approval_pending
            ? `Submitted for a second admin's approval (request ${res.approval_request_id?.slice(0, 8)}…).`
            : `Change request ${res.status}.`,
        );
        this.load();
      },
      error: (e: ApiError) => { this.decidingId.set(null); this.error.set(e.message); },
    });
  }
}
