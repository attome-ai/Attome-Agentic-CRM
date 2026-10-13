import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';
import { EntityService } from '../services/entity.service';

/** `platform-bundles/attome-api-activity.json` — basic-units U2, D-600. */
export const ACTIVITY_ENTITY = 'activity';

export type ActivityType = 'task' | 'phone_call';
export type ActivityStatus = 'open' | 'completed' | 'cancelled';

export interface ActivityRow {
  id: string;
  subject: string;
  activity_type: ActivityType;
  status: ActivityStatus;
  due_at: string | null;
  completed_at: string | null;
  direction: string | null;
  row_version: number;
}

/**
 * Open activities first (earliest due first, undated last), then the closed
 * ones, most recently completed first. Pure, so the spec can pin it.
 */
export function sortActivities(rows: readonly ActivityRow[]): ActivityRow[] {
  const time = (v: string | null) => (v ? Date.parse(v) : Number.NaN);
  return [...rows].sort((a, b) => {
    const aOpen = a.status === 'open';
    const bOpen = b.status === 'open';
    if (aOpen !== bOpen) return aOpen ? -1 : 1;
    if (aOpen) {
      const ad = time(a.due_at);
      const bd = time(b.due_at);
      if (Number.isNaN(ad) !== Number.isNaN(bd)) return Number.isNaN(ad) ? 1 : -1;
      if (!Number.isNaN(ad) && ad !== bd) return ad - bd;
      return a.subject.localeCompare(b.subject);
    }
    const ac = time(a.completed_at);
    const bc = time(b.completed_at);
    return (Number.isNaN(bc) ? 0 : bc) - (Number.isNaN(ac) ? 0 : ac);
  });
}

/** An open activity whose due time has passed. */
export function isOverdue(row: ActivityRow, now: number = Date.now()): boolean {
  if (row.status !== 'open' || !row.due_at) return false;
  const due = Date.parse(row.due_at);
  return !Number.isNaN(due) && due < now;
}

/**
 * The Activities record tab (basic-units U2): the tasks and phone calls
 * attached to one record through `activity`'s `entity_name`/`record_id`
 * pair. Everything goes through the generic entity API: the list is
 * `query/execute` on the entity's default query, quick-create is a plain
 * create, and Complete is a PATCH of `status` (plus `completed_at`) that the
 * seeded state model checks exactly as it checks any other write. The server
 * also refuses an activity on a record the caller cannot read (D-593), so
 * this panel never decides visibility itself.
 */
@Component({
  selector: 'xrm-activities-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, FormsModule, TranslatePipe],
  styleUrls: ['./activities-panel.component.css'],
  templateUrl: './activities-panel.component.html',
})
export class ActivitiesPanelComponent {
  readonly entityName = input.required<string>();
  readonly recordId = input.required<string>();

  private readonly entityService = inject(EntityService);
  private readonly lang = inject(LangService);

  readonly loading = signal(true);
  readonly saving = signal(false);
  readonly busyId = signal<string | null>(null);
  readonly errorMessage = signal<string | null>(null);
  readonly rows = signal<ActivityRow[]>([]);
  readonly sorted = computed(() => sortActivities(this.rows()));

  newType: ActivityType = 'task';
  newSubject = '';
  newDueAt = '';
  newDirection: 'inbound' | 'outbound' = 'outbound';

  constructor() {
    effect(() => {
      const e = this.entityName();
      const r = this.recordId();
      untracked(() => {
        if (e && r) this.load();
      });
    });
  }

  load(): void {
    this.loading.set(true);
    this.errorMessage.set(null);
    this.entityService.list(ACTIVITY_ENTITY, {
      filters: [
        { field: 'entity_name', op: 'eq', value: this.entityName() },
        { field: 'record_id', op: 'eq', value: this.recordId() },
      ],
      limit: 200,
    }).subscribe({
      next: res => {
        this.rows.set(res.data.map(item => {
          const raw = item.data as Record<string, unknown>;
          const text = (k: string) => (raw[k] == null ? null : String(raw[k]));
          return {
            id: item.id,
            subject: String(raw['subject'] ?? ''),
            activity_type: (raw['activity_type'] === 'phone_call' ? 'phone_call' : 'task') as ActivityType,
            status: (text('status') ?? 'open') as ActivityStatus,
            due_at: text('due_at'),
            completed_at: text('completed_at'),
            direction: text('direction'),
            row_version: item.row_version,
          };
        }));
        this.loading.set(false);
      },
      error: err => {
        this.rows.set([]);
        this.loading.set(false);
        this.errorMessage.set(err?.message || this.lang.translate('activitiesPanel.loadFailed'));
      },
    });
  }

  overdue(row: ActivityRow): boolean {
    return isOverdue(row);
  }

  add(): void {
    const subject = this.newSubject.trim();
    if (!subject || this.saving()) return;
    const body: Record<string, unknown> = {
      subject,
      activity_type: this.newType,
      entity_name: this.entityName(),
      record_id: this.recordId(),
    };
    if (this.newDueAt) {
      const due = new Date(this.newDueAt);
      if (!Number.isNaN(due.getTime())) body['due_at'] = due.toISOString();
    }
    if (this.newType === 'phone_call') body['direction'] = this.newDirection;

    this.saving.set(true);
    this.errorMessage.set(null);
    this.entityService.create(ACTIVITY_ENTITY, body).subscribe({
      next: () => {
        this.saving.set(false);
        this.newSubject = '';
        this.newDueAt = '';
        this.load();
      },
      error: err => {
        this.saving.set(false);
        this.errorMessage.set(err?.message || this.lang.translate('activitiesPanel.saveFailed'));
      },
    });
  }

  complete(row: ActivityRow): void {
    if (row.status !== 'open' || this.busyId()) return;
    this.busyId.set(row.id);
    this.errorMessage.set(null);
    this.entityService.update(
      ACTIVITY_ENTITY,
      row.id,
      { status: 'completed', completed_at: new Date().toISOString() },
      row.row_version,
    ).subscribe({
      next: () => {
        this.busyId.set(null);
        this.load();
      },
      error: err => {
        this.busyId.set(null);
        this.errorMessage.set(err?.message || this.lang.translate('activitiesPanel.saveFailed'));
      },
    });
  }
}
