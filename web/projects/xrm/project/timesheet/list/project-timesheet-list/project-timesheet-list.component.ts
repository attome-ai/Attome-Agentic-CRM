import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { ApiError } from '@attome/base';
import { EntityRecord } from '@attome/xrm';
import { EntityService } from '@attome/xrm/core/entity';
import { ProjectService, TimesheetDecisionResponse } from '../../../services/project.service';

const ENTITY = 'project_timesheet';
const STATUS_FILTERS = ['all', 'draft', 'submitted', 'approved', 'rejected'] as const;
type StatusFilter = (typeof STATUS_FILTERS)[number];

/**
 * Timesheets — `crates/engine/attome-project/src/timesheet.rs`'s M07 state model +
 * D-195/D-421 four-eyes gate (submit/approve/reject), previously API-only.
 * Not scoped to one project: `project_timesheet` carries `user_id` +
 * `week_start_date` only (which project(s) it covers comes from its
 * `project_time_entry` children, each pointing at a work item), so this
 * is a standalone list — same "not scoped to one project" posture
 * `ResourceCapacityPageComponent` already takes for the same reason.
 */
@Component({
  selector: 'attome-project-timesheet-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, DatePipe],
  styleUrls: ['./project-timesheet-list.component.css'],
  templateUrl: './project-timesheet-list.component.html',
})
export class ProjectTimesheetListComponent implements OnInit {
  private readonly entitySvc = inject(EntityService);
  private readonly projectSvc = inject(ProjectService);

  readonly statusOptions = STATUS_FILTERS;
  readonly statusFilter = signal<StatusFilter>('submitted');

  readonly rows = signal<EntityRecord[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly decidingId = signal<string | null>(null);
  readonly note = signal<string | null>(null);

  ngOnInit(): void { this.load(); }

  setStatusFilter(value: StatusFilter): void {
    this.statusFilter.set(value);
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    const filter = this.statusFilter();
    this.entitySvc
      .list(ENTITY, {
        filters: filter === 'all' ? [] : [{ field: 'status', op: 'eq', value: filter }],
        sorts: [{ field: 'week_start_date', dir: 'desc' }],
        limit: 100,
      })
      .subscribe({
        next: res => { this.rows.set(res.data); this.loading.set(false); },
        error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
      });
  }

  status(r: EntityRecord): string { return String(r.data['status'] ?? ''); }

  weekStart(r: EntityRecord): string | null {
    const v = r.data['week_start_date'];
    return v == null ? null : String(v);
  }

  approvedAt(r: EntityRecord): string | null {
    const v = r.data['approved_at'];
    return v == null ? null : String(v);
  }

  shortId(id: unknown): string {
    return id == null || id === '' ? '—' : String(id).slice(0, 8);
  }

  submit(r: EntityRecord): void { this.decide(r, this.projectSvc.submitTimesheet(r.id)); }
  approve(r: EntityRecord): void { this.decide(r, this.projectSvc.approveTimesheet(r.id)); }
  reject(r: EntityRecord): void { this.decide(r, this.projectSvc.rejectTimesheet(r.id)); }

  private decide(r: EntityRecord, call: ReturnType<ProjectService['submitTimesheet']>): void {
    this.decidingId.set(r.id);
    this.note.set(null);
    call.subscribe({
      next: (res: TimesheetDecisionResponse) => {
        this.decidingId.set(null);
        this.note.set(
          res.approval_pending
            ? `Submitted for a second admin's approval (request ${res.approval_request_id?.slice(0, 8)}…).`
            : `Timesheet ${res.status}.`,
        );
        this.load();
      },
      error: (e: ApiError) => { this.decidingId.set(null); this.error.set(e.message); },
    });
  }
}
