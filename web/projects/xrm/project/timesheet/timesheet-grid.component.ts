import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { ApiError, ApiService, AuthService, LangService, TranslatePipe } from '@attome/base';
import type { EntityRecord } from '@attome/xrm';
import { EntityService } from '@attome/xrm/core/entity';
import { Observable, catchError, forkJoin, map, of, switchMap } from 'rxjs';
import { ProjectService } from '../services/project.service';

const TIMESHEET = 'project_timesheet';
const ENTRY = 'project_time_entry';
const WORK_ITEM = 'project_work_item';
/** A timesheet its owner may still change. */
const EDITABLE = new Set(['draft', 'rejected']);
/** Hours one cell may hold. */
const MAX_HOURS = 24;

/** One saved entry, as the grid needs it. */
interface Entry {
  id: string;
  rowVersion: number;
  workItemId: string;
  date: string;
  hours: number;
}

/** One work item's row: its name and an entry per day of the week. */
interface Row {
  workItemId: string;
  name: string;
}

/** `GET /api/v1/hr/availability`: the days a person is away on approved leave. */
interface Availability {
  away: string[];
}

/** `YYYY-MM-DD` for a local date. */
export function isoDate(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** The Sunday a week starts on (the Gulf working week runs Sunday to Thursday). */
export function weekStartOf(d: Date): Date {
  return new Date(d.getFullYear(), d.getMonth(), d.getDate() - d.getDay());
}

/** The seven dates of the week starting `start`. */
export function weekDays(start: Date): string[] {
  return Array.from({ length: 7 }, (_, i) =>
    isoDate(new Date(start.getFullYear(), start.getMonth(), start.getDate() + i)));
}

/**
 * V3-T1 — my week's timesheet as a grid: a row per work item, a column per
 * day, hours in each cell. Days the person is away on approved leave (W6,
 * `GET /api/v1/hr/availability`) are marked and take no hours. A cell saves
 * when it loses focus: the week's `project_timesheet` is created on the first
 * hours entered, and each cell is one `project_time_entry`, created, changed
 * or deleted through the entity API. Submit sends the week for approval
 * (`POST /api/v1/project/timesheet/{id}/submit`); after that the grid is
 * read-only until the week is rejected.
 */
@Component({
  selector: 'xrm-timesheet-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./timesheet-grid.component.css'],
  template: `
    <section class="ts" data-timesheet-grid>
      <header class="ts-head">
        <h2>{{ 'timesheetGrid.title' | translate }}</h2>
        <div class="ts-week">
          <button type="button" class="ts-btn" (click)="move(-7)" [disabled]="busy()" data-week-prev>
            {{ 'timesheetGrid.previousWeek' | translate }}
          </button>
          <span class="ts-week-label" data-week-label>{{ weekLabel() }}</span>
          <button type="button" class="ts-btn" (click)="move(7)" [disabled]="busy()" data-week-next>
            {{ 'timesheetGrid.nextWeek' | translate }}
          </button>
        </div>
        <span class="ts-status" data-timesheet-status>
          {{ ('timesheetGrid.status.' + status()) | translate }}
        </span>
      </header>

      @if (error(); as e) {
        <p class="ts-error" role="alert">{{ e }}</p>
      }
      @if (notice(); as n) {
        <p class="ts-note" role="status">{{ n }}</p>
      }

      @if (loading()) {
        <p class="ts-note">{{ 'timesheetGrid.loading' | translate }}</p>
      } @else {
        <div class="ts-wrap">
          <table class="ts-table">
            <thead>
              <tr>
                <th scope="col">{{ 'timesheetGrid.workItem' | translate }}</th>
                @for (day of days(); track day) {
                  <th scope="col" [class.ts-away]="isAway(day)" [attr.data-day]="day">
                    {{ dayLabel(day) }}
                    @if (isAway(day)) {
                      <span class="ts-badge" data-away>{{ 'timesheetGrid.onLeave' | translate }}</span>
                    }
                  </th>
                }
                <th scope="col">{{ 'timesheetGrid.total' | translate }}</th>
              </tr>
            </thead>
            <tbody>
              @for (row of rows(); track row.workItemId) {
                <tr [attr.data-row]="row.workItemId">
                  <th scope="row">{{ row.name }}</th>
                  @for (day of days(); track day) {
                    <td [class.ts-away]="isAway(day)">
                      <input type="number" class="ts-cell" min="0" [max]="maxHours" step="0.25"
                             inputmode="decimal"
                             [attr.aria-label]="'timesheetGrid.cellLabel' | translate: { item: row.name, day: dayLabel(day) }"
                             [value]="cell(row.workItemId, day) ?? ''"
                             [disabled]="!editable() || isAway(day) || busy()"
                             (change)="save(row.workItemId, day, $any($event.target).value)"
                             [attr.data-cell]="row.workItemId + '|' + day">
                    </td>
                  }
                  <td class="ts-total" [attr.data-row-total]="row.workItemId">{{ hours(rowTotal(row.workItemId)) }}</td>
                </tr>
              } @empty {
                <tr>
                  <td [attr.colspan]="days().length + 2" class="ts-note">{{ 'timesheetGrid.empty' | translate }}</td>
                </tr>
              }
            </tbody>
            <tfoot>
              <tr>
                <th scope="row">{{ 'timesheetGrid.total' | translate }}</th>
                @for (day of days(); track day) {
                  <td class="ts-total">{{ hours(dayTotal(day)) }}</td>
                }
                <td class="ts-total" data-week-total>{{ hours(weekTotal()) }}</td>
              </tr>
            </tfoot>
          </table>
        </div>

        @if (editable()) {
          <div class="ts-add">
            <label class="ts-field">
              <span>{{ 'timesheetGrid.addWorkItem' | translate }}</span>
              <input type="search" [value]="search()" (input)="find($any($event.target).value)"
                     [placeholder]="'timesheetGrid.searchWorkItems' | translate" data-work-item-search>
            </label>
            @if (found().length) {
              <ul class="ts-found" role="listbox" [attr.aria-label]="'timesheetGrid.addWorkItem' | translate">
                @for (item of found(); track item.workItemId) {
                  <li role="option" [attr.aria-selected]="false">
                    <button type="button" class="ts-btn" (click)="addRow(item)" [attr.data-add]="item.workItemId">
                      {{ item.name }}
                    </button>
                  </li>
                }
              </ul>
            }
          </div>
          <div class="ts-actions">
            <button type="button" class="ts-btn ts-primary" (click)="submit()"
                    [disabled]="busy() || !timesheetId() || weekTotal() === 0" data-submit>
              {{ 'timesheetGrid.submit' | translate }}
            </button>
          </div>
        }
      }
    </section>
  `,
})
export class TimesheetGridComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly auth = inject(AuthService);
  private readonly lang = inject(LangService);
  private readonly entities = inject(EntityService);
  private readonly project = inject(ProjectService);

  readonly maxHours = MAX_HOURS;
  readonly weekStart = signal(weekStartOf(new Date()));
  readonly days = computed(() => weekDays(this.weekStart()));
  readonly timesheetId = signal<string | null>(null);
  readonly status = signal('draft');
  readonly editable = computed(() => EDITABLE.has(this.status()));
  readonly entries = signal<Entry[]>([]);
  readonly extraRows = signal<Row[]>([]);
  readonly away = signal<ReadonlySet<string>>(new Set());
  readonly loading = signal(true);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly search = signal('');
  readonly found = signal<Row[]>([]);
  private names = new Map<string, string>();

  /** A row for every work item with an entry, then the ones added by hand. */
  readonly rows = computed<Row[]>(() => {
    const seen = new Set<string>();
    const rows: Row[] = [];
    for (const e of this.entries()) {
      if (seen.has(e.workItemId)) continue;
      seen.add(e.workItemId);
      rows.push({ workItemId: e.workItemId, name: this.names.get(e.workItemId) ?? e.workItemId });
    }
    for (const r of this.extraRows()) {
      if (!seen.has(r.workItemId)) {
        seen.add(r.workItemId);
        rows.push(r);
      }
    }
    return rows;
  });

  readonly weekTotal = computed(() => this.entries().reduce((sum, e) => sum + e.hours, 0));

  ngOnInit(): void {
    this.load();
  }

  weekLabel(): string {
    const days = this.days();
    return `${this.dayLabel(days[0])} – ${this.dayLabel(days[days.length - 1])}`;
  }

  dayLabel(day: string): string {
    const [y, m, d] = day.split('-').map(Number);
    return new Intl.DateTimeFormat(this.lang.intlLocale(), { weekday: 'short', day: 'numeric', month: 'short' })
      .format(new Date(y, m - 1, d));
  }

  hours(n: number): string {
    return new Intl.NumberFormat(this.lang.intlLocale(), { maximumFractionDigits: 2 }).format(n);
  }

  isAway(day: string): boolean {
    return this.away().has(day);
  }

  cell(workItemId: string, day: string): number | null {
    return this.entries().find(e => e.workItemId === workItemId && e.date === day)?.hours ?? null;
  }

  rowTotal(workItemId: string): number {
    return this.entries().filter(e => e.workItemId === workItemId).reduce((s, e) => s + e.hours, 0);
  }

  dayTotal(day: string): number {
    return this.entries().filter(e => e.date === day).reduce((s, e) => s + e.hours, 0);
  }

  move(days: number): void {
    const s = this.weekStart();
    this.weekStart.set(new Date(s.getFullYear(), s.getMonth(), s.getDate() + days));
    this.extraRows.set([]);
    this.load();
  }

  find(text: string): void {
    this.search.set(text);
    if (text.trim().length < 2) {
      this.found.set([]);
      return;
    }
    this.entities.lookupSearch(WORK_ITEM, text, 'name').subscribe({
      next: res => this.found.set(res.data.map(r => ({ workItemId: r.id, name: String(r.data['name'] ?? r.id) }))),
      error: () => this.found.set([]),
    });
  }

  addRow(item: Row): void {
    this.names.set(item.workItemId, item.name);
    this.extraRows.update(rows => [...rows, item]);
    this.search.set('');
    this.found.set([]);
  }

  /** Saves one cell: an empty or zero value removes its entry. */
  save(workItemId: string, day: string, raw: string): void {
    const value = raw.trim() === '' ? 0 : Number(raw);
    if (!Number.isFinite(value) || value < 0 || value > MAX_HOURS) {
      this.error.set(this.lang.translate('timesheetGrid.invalidHours', { max: MAX_HOURS }));
      return;
    }
    const existing = this.entries().find(e => e.workItemId === workItemId && e.date === day);
    let call: Observable<unknown>;
    if (existing && value === 0) {
      call = this.entities.delete(ENTRY, existing.id);
    } else if (existing) {
      call = this.entities.update(ENTRY, existing.id, { hours: value }, existing.rowVersion);
    } else if (value === 0) {
      return;
    } else {
      call = this.ensureTimesheet().pipe(
        switchMap(timesheetId => this.entities.create(ENTRY, {
          timesheet_id: timesheetId,
          work_item_id: workItemId,
          user_id: this.auth.userId(),
          entry_date: day,
          hours: value,
        })),
      );
    }
    this.busy.set(true);
    this.error.set(null);
    call.subscribe({
      next: () => {
        this.busy.set(false);
        this.reloadEntries();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
        this.reloadEntries();
      },
    });
  }

  submit(): void {
    const id = this.timesheetId();
    if (!id) return;
    this.busy.set(true);
    this.error.set(null);
    this.project.submitTimesheet(id).subscribe({
      next: res => {
        this.busy.set(false);
        this.status.set(res.status);
        this.notice.set(this.lang.translate(res.approval_pending ? 'timesheetGrid.submittedForApproval' : 'timesheetGrid.submitted'));
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  private load(): void {
    const user = this.auth.userId();
    if (!user) return;
    const days = this.days();
    this.loading.set(true);
    this.error.set(null);
    this.notice.set(null);
    this.timesheetId.set(null);
    this.status.set('draft');
    this.entries.set([]);
    const timesheet$ = this.entities.list(TIMESHEET, {
      filters: [
        { field: 'user_id', op: 'eq', value: user },
        { field: 'week_start_date', op: 'eq', value: days[0] },
      ],
      limit: 1,
    }).pipe(map(res => res.data[0] ?? null));
    // A person without `employee.read`, or a deployment without the HR pack,
    // has no leave to show: the grid opens without it.
    const away$ = this.api.get<Availability>('/api/v1/hr/availability', {
      user_id: user,
      from: days[0],
      to: days[days.length - 1],
    }).pipe(
      map(a => new Set(a.away)),
      catchError(() => of(new Set<string>())),
    );
    forkJoin([timesheet$, away$]).subscribe({
      next: ([timesheet, away]) => {
        this.away.set(away);
        if (timesheet) {
          this.timesheetId.set(timesheet.id);
          this.status.set(String(timesheet.data['status'] ?? 'draft'));
          this.reloadEntries();
        } else {
          this.loading.set(false);
        }
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  private reloadEntries(): void {
    const id = this.timesheetId();
    if (!id) {
      this.loading.set(false);
      return;
    }
    this.entities.list(ENTRY, {
      filters: [{ field: 'timesheet_id', op: 'eq', value: id }],
      sorts: [{ field: 'entry_date', dir: 'asc' }],
      limit: 500,
    }).subscribe({
      next: res => {
        this.entries.set(res.data.map(r => this.toEntry(r)));
        this.loading.set(false);
      },
      error: (e: ApiError) => {
        this.error.set(this.lang.errorText(e));
        this.loading.set(false);
      },
    });
  }

  private toEntry(r: EntityRecord): Entry {
    const workItemId = String(r.data['work_item_id'] ?? '');
    const lookups = r.data['__lookups'] as Record<string, { name?: string | null }> | undefined;
    const name = lookups?.['work_item_id']?.name;
    if (name) this.names.set(workItemId, name);
    return {
      id: r.id,
      rowVersion: r.row_version,
      workItemId,
      date: String(r.data['entry_date'] ?? '').slice(0, 10),
      hours: Number(r.data['hours'] ?? 0),
    };
  }

  /** The week's timesheet id, creating the draft on the first hours entered. */
  private ensureTimesheet(): Observable<string> {
    const id = this.timesheetId();
    if (id) return of(id);
    // The state model gives a new timesheet its initial state (draft).
    return this.entities.create(TIMESHEET, {
      user_id: this.auth.userId(),
      week_start_date: this.days()[0],
    }).pipe(
      map(res => {
        const created = String(res.id ?? '');
        this.timesheetId.set(created);
        return created;
      }),
    );
  }
}
