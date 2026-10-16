import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { concatMap, of } from 'rxjs';
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

/** D14-T2: what the quick call log asks for. */
export interface CallLog {
  subject: string;
  direction: 'inbound' | 'outbound';
  minutes: number | null;
  notes: string;
  outcome: string;
  nextSubject: string;
  /** A `datetime-local` value, or empty. */
  nextDue: string;
}

/** The body that creates the logged call on `entity`/`record`. Pure. */
export function callBody(log: CallLog, entity: string, record: string): Record<string, unknown> {
  const body: Record<string, unknown> = {
    subject: log.subject,
    activity_type: 'phone_call',
    direction: log.direction,
    entity_name: entity,
    record_id: record,
  };
  if (log.minutes !== null && log.minutes > 0) body['duration_minutes'] = log.minutes;
  if (log.notes.trim()) body['description'] = log.notes.trim();
  if (log.outcome) body['outcome'] = log.outcome;
  return body;
}

/** The next-step task to create after the call, or `null` when none. Pure. */
export function nextStepBody(log: CallLog, entity: string, record: string): Record<string, unknown> | null {
  const subject = log.nextSubject.trim();
  if (!subject) return null;
  const body: Record<string, unknown> = {
    subject, activity_type: 'task', entity_name: entity, record_id: record,
  };
  if (log.nextDue) {
    const due = new Date(log.nextDue);
    if (!Number.isNaN(due.getTime())) body['due_at'] = due.toISOString();
  }
  return body;
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

  /** D14-T2: the quick call log. */
  readonly logOpen = signal(false);
  /** The activity entity's `outcome` choices, when a pack adds that field. */
  readonly outcomes = signal<string[]>([]);
  log: CallLog = this.emptyLog();

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

  private emptyLog(): CallLog {
    return {
      subject: '', direction: 'outbound', minutes: null, notes: '', outcome: '',
      nextSubject: '', nextDue: '',
    };
  }

  openLog(): void {
    this.log = this.emptyLog();
    this.logOpen.set(true);
    if (this.outcomes().length > 0) return;
    this.entityService.getSchema(ACTIVITY_ENTITY).subscribe({
      next: schema => {
        const field = schema.fields.find(f => f.name === 'outcome' && f.field_type === 'choice');
        const choices = (field?.options as unknown as { choices?: string[] } | null | undefined)?.choices;
        this.outcomes.set(Array.isArray(choices) ? choices : []);
      },
      // Without the schema the log still works, just without an outcome.
      error: () => this.outcomes.set([]),
    });
  }

  closeLog(): void {
    this.logOpen.set(false);
  }

  /**
   * D14-T2: logs a call that already happened in one step — created, then
   * completed through the state model like any other activity — and, when
   * a next step is named, adds it as a task.
   */
  logCall(): void {
    if (this.saving()) return;
    const log: CallLog = {
      ...this.log,
      subject: this.log.subject.trim() || this.lang.translate('activitiesPanel.callSubject'),
    };
    const entity = this.entityName();
    const record = this.recordId();
    const next = nextStepBody(log, entity, record);
    this.saving.set(true);
    this.errorMessage.set(null);
    this.entityService.create(ACTIVITY_ENTITY, callBody(log, entity, record)).pipe(
      concatMap(call => this.entityService.update(
        ACTIVITY_ENTITY,
        call.id,
        { status: 'completed', completed_at: new Date().toISOString() },
        call.row_version,
      )),
      concatMap(() => (next ? this.entityService.create(ACTIVITY_ENTITY, next) : of(null))),
    ).subscribe({
      next: () => {
        this.saving.set(false);
        this.logOpen.set(false);
        this.load();
      },
      error: err => {
        this.saving.set(false);
        this.errorMessage.set(err?.message || this.lang.translate('activitiesPanel.saveFailed'));
        this.load();
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
