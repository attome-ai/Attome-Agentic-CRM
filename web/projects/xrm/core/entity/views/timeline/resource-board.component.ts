import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { ApiError, ApiService, LangService, TranslatePipe } from '@attome/base';
import { QueryService } from '@attome/xrm/core/query/data';
import { Observable, catchError, forkJoin, map, of } from 'rxjs';

import { EntityService } from '../../services/entity.service';

/** The day the board shows, in hours from midnight UTC. */
export const DAY_FROM_HOUR = 6;
export const DAY_TO_HOUR = 20;

/** A technician row: the technician profile and the user it names. */
export interface BoardTechnician { profileId: string; userId: string; name: string; }

/** A job on the board. */
export interface BoardJob {
  id: string;
  title: string;
  start: string | null;
  end: string | null;
  assignedTo: string | null;
  rowVersion: number;
}

/** A proposed visit from the day plan (I2-T2's `Ghost`). */
export interface BoardGhost {
  work_order_id: string;
  technician_id: string;
  sequence: number;
  start: string;
  end: string;
  travel_minutes: number;
}

/** Where a bar sits on the day, as percentages of the day's width. Pure. */
export function barGeometry(start: string | null, end: string | null, date: string): { offset: number; width: number } | null {
  if (!start) return null;
  const from = Date.parse(`${date}T${String(DAY_FROM_HOUR).padStart(2, '0')}:00:00Z`);
  const to = Date.parse(`${date}T${String(DAY_TO_HOUR).padStart(2, '0')}:00:00Z`);
  const s = Date.parse(start);
  const e = end ? Date.parse(end) : s + 60 * 60 * 1000;
  if (Number.isNaN(s) || e <= from || s >= to) return null;
  const span = to - from;
  const left = Math.max(0, (s - from) / span) * 100;
  const right = Math.min(1, (e - from) / span) * 100;
  return { offset: left, width: Math.max(1, right - left) };
}

/** The hours the time axis labels. Pure. */
export function axisHours(): number[] {
  return Array.from({ length: DAY_TO_HOUR - DAY_FROM_HOUR }, (_, i) => DAY_FROM_HOUR + i);
}

interface CandidateList { work_order_id: string; rules: string[]; candidates: { user_id: string }[]; }

/**
 * I3-T1 — the dispatch board, the timeline's resource mode: one row per
 * technician (`technician_profile`), the day's work orders as bars on their
 * technician's row, and the unassigned ones beside it. Dropping a job on a
 * technician first checks the hard rules on the device (the work order's
 * candidates, I2-T1: skills, territory, hours and van parts) and refuses a
 * technician who fails them; the assignment is then written with the work
 * order's row version (`If-Match`), so the server checks it again and a
 * stale board is told to reload. "Propose the day" asks the planner (I2-T2)
 * for ghost bars, each accepted or rejected on its own. The time axis runs
 * in the reading direction, so it mirrors in Arabic.
 */
@Component({
  selector: 'xrm-resource-board',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="rb" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" data-testid="resource-board">
      <header class="rb-head">
        <h2>{{ 'resourceBoard.title' | translate }} <span dir="ltr">{{ date() }}</span></h2>
        <button type="button" data-testid="rb-propose" [disabled]="busy()" (click)="propose()">{{ 'resourceBoard.propose' | translate }}</button>
      </header>
      @if (message(); as m) { <p class="rb-message" role="alert" data-testid="rb-message">{{ m }}</p> }
      <div class="rb-layout">
        <div class="rb-grid" role="grid" [attr.aria-label]="'resourceBoard.grid' | translate">
          <div class="rb-row rb-axis" role="row">
            <div class="rb-name" role="columnheader">{{ 'resourceBoard.technician' | translate }}</div>
            <div class="rb-track rb-hours" role="columnheader">
              @for (h of hours; track h) { <span dir="ltr">{{ h }}:00</span> }
            </div>
          </div>
          @for (t of technicians(); track t.userId) {
            <div class="rb-row" role="row" data-testid="rb-row" [attr.data-user]="t.userId"
                 (dragover)="$event.preventDefault()" (drop)="drop($event, t)">
              <div class="rb-name" role="rowheader">{{ t.name }}</div>
              <div class="rb-track" role="gridcell">
                @for (j of jobsOf(t.userId); track j.id) {
                  @if (geometry(j); as g) {
                    <div class="rb-bar" draggable="true" data-testid="rb-bar" [attr.data-job]="j.id"
                         [style.inset-inline-start.%]="g.offset" [style.inline-size.%]="g.width"
                         (dragstart)="dragStart(j)">{{ j.title }}</div>
                  }
                }
                @for (g of ghostsOf(t.userId); track g.work_order_id) {
                  @if (ghostGeometry(g); as geo) {
                    <div class="rb-bar rb-ghost" data-testid="rb-ghost" [attr.data-job]="g.work_order_id"
                         [style.inset-inline-start.%]="geo.offset" [style.inline-size.%]="geo.width">
                      <span>{{ titleOf(g.work_order_id) }}</span>
                      <button type="button" data-testid="rb-accept" [attr.aria-label]="'resourceBoard.accept' | translate" (click)="accept(g)">✓</button>
                      <button type="button" data-testid="rb-reject" [attr.aria-label]="'resourceBoard.reject' | translate" (click)="reject(g)">✕</button>
                    </div>
                  }
                }
              </div>
            </div>
          } @empty {
            <p class="rb-muted">{{ 'resourceBoard.noTechnicians' | translate }}</p>
          }
        </div>
        <aside class="rb-unassigned" [attr.aria-label]="'resourceBoard.unassigned' | translate">
          <h3>{{ 'resourceBoard.unassigned' | translate }}</h3>
          <ul>
            @for (j of unassigned(); track j.id) {
              <li draggable="true" data-testid="rb-unassigned" [attr.data-job]="j.id" (dragstart)="dragStart(j)">{{ j.title }}</li>
            } @empty {
              <li class="rb-muted">{{ 'resourceBoard.allAssigned' | translate }}</li>
            }
          </ul>
        </aside>
      </div>
    </section>
  `,
  styles: [`
    .rb { display: grid; gap: .75rem; }
    .rb-head { display: flex; justify-content: space-between; align-items: center; gap: .5rem; }
    .rb-head h2 { margin: 0; }
    .rb-layout { display: grid; grid-template-columns: minmax(0, 1fr) 14rem; gap: .75rem; }
    @media (max-width: 48rem) { .rb-layout { grid-template-columns: minmax(0, 1fr); } }
    .rb-grid { overflow-x: auto; border: 1px solid var(--color-border, #ddd); border-radius: 8px; }
    .rb-row { display: grid; grid-template-columns: 10rem minmax(36rem, 1fr); border-block-end: 1px solid var(--color-border, #eee); min-block-size: 2.5rem; }
    .rb-name { padding: .5rem; font-weight: 600; border-inline-end: 1px solid var(--color-border, #eee); }
    .rb-track { position: relative; }
    .rb-hours { display: grid; grid-auto-flow: column; grid-auto-columns: 1fr; font-size: .7rem; color: var(--color-text-secondary, #666); padding-block: .25rem; }
    .rb-bar { position: absolute; inset-block: .35rem; overflow: hidden; white-space: nowrap; text-overflow: ellipsis;
              padding-inline: .375rem; font-size: .75rem; border-radius: 4px; cursor: grab;
              background: var(--color-primary-bg, #e3edf9); border: 1px solid var(--color-primary, #2b6cb0); }
    .rb-ghost { border-style: dashed; background: var(--color-bg-alt, #f7f7f7); display: flex; gap: .25rem; align-items: center; cursor: default; }
    .rb-ghost button { padding: 0 .25rem; font-size: .7rem; }
    .rb-unassigned { border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .5rem; }
    .rb-unassigned h3 { margin: 0 0 .5rem; font-size: .875rem; }
    .rb-unassigned ul { list-style: none; margin: 0; padding: 0; display: grid; gap: .25rem; }
    .rb-unassigned li[draggable] { padding: .375rem; border: 1px solid var(--color-border, #ccc); border-radius: 4px; cursor: grab; }
    .rb-message { color: var(--color-danger, #c53030); margin: 0; }
    .rb-muted { color: var(--color-text-secondary, #666); }
  `],
})
export class ResourceBoardComponent {
  private readonly api = inject(ApiService);
  private readonly query = inject(QueryService);
  private readonly entities = inject(EntityService);
  protected readonly lang = inject(LangService);

  /** The day shown, `YYYY-MM-DD` (UTC); today when unset. */
  readonly day = input<string | undefined>(undefined);

  readonly hours = axisHours();
  readonly technicians = signal<BoardTechnician[]>([]);
  readonly jobs = signal<BoardJob[]>([]);
  readonly ghosts = signal<BoardGhost[]>([]);
  readonly message = signal<string | null>(null);
  readonly busy = signal(false);
  private dragged: BoardJob | null = null;
  private readonly candidates = new Map<string, CandidateList>();

  readonly date = computed(() => this.day() ?? new Date().toISOString().slice(0, 10));
  readonly unassigned = computed(() => this.jobs().filter(j => !j.assignedTo));

  constructor() {
    effect(() => {
      const date = this.date();
      untracked(() => this.load(date));
    });
  }

  jobsOf(userId: string): BoardJob[] {
    return this.jobs().filter(j => j.assignedTo === userId);
  }

  ghostsOf(userId: string): BoardGhost[] {
    return this.ghosts().filter(g => g.technician_id === userId);
  }

  geometry(j: BoardJob) {
    return barGeometry(j.start, j.end, this.date());
  }

  ghostGeometry(g: BoardGhost) {
    return barGeometry(g.start, g.end, this.date());
  }

  titleOf(jobId: string): string {
    return this.jobs().find(j => j.id === jobId)?.title ?? jobId;
  }

  dragStart(job: BoardJob): void {
    this.dragged = job;
  }

  /** Assigns the dragged job to `tech` once the hard rules allow it. */
  drop(event: Event, tech: BoardTechnician): void {
    event.preventDefault();
    const job = this.dragged;
    this.dragged = null;
    if (!job || job.assignedTo === tech.userId) return;
    this.message.set(null);
    this.candidatesOf(job.id).subscribe(list => {
      if (!list) return;
      if (!list.candidates.some(c => c.user_id === tech.userId)) {
        this.message.set(this.lang.translate('resourceBoard.refused', { name: tech.name, rules: list.rules.join(', ') }));
        return;
      }
      this.assign(job, tech.userId, {});
    });
  }

  /** Puts a proposed visit on the board for real. */
  accept(g: BoardGhost): void {
    const job = this.jobs().find(j => j.id === g.work_order_id);
    if (!job) return;
    this.assign(job, g.technician_id, { scheduled_start: g.start, scheduled_end: g.end }, () =>
      this.ghosts.update(list => list.filter(x => x.work_order_id !== g.work_order_id)));
  }

  reject(g: BoardGhost): void {
    this.ghosts.update(list => list.filter(x => x.work_order_id !== g.work_order_id));
  }

  /** Asks the planner for the day's ghost visits. */
  propose(): void {
    this.busy.set(true);
    this.message.set(null);
    this.api.post<{ assignments: BoardGhost[]; unassigned: string[] }>('/api/v1/service/day-plans/propose', { date: this.date() }).subscribe({
      next: plan => { this.ghosts.set(plan.assignments); this.busy.set(false); },
      error: (e: ApiError) => { this.busy.set(false); this.message.set(this.lang.errorText(e)); },
    });
  }

  private candidatesOf(jobId: string): Observable<CandidateList | null> {
    const cached = this.candidates.get(jobId);
    if (cached) return of(cached);
    return this.api.get<CandidateList>(`/api/v1/service/work-orders/${encodeURIComponent(jobId)}/candidates`).pipe(
      map(list => { this.candidates.set(jobId, list); return list; }),
      catchError((e: ApiError) => { this.message.set(this.lang.errorText(e)); return of(null); }),
    );
  }

  private assign(job: BoardJob, userId: string, extra: Record<string, unknown>, done?: () => void): void {
    this.busy.set(true);
    this.entities.update('work_order', job.id, { assigned_to: userId, ...extra }, job.rowVersion).subscribe({
      next: saved => {
        this.busy.set(false);
        const rv = Number((saved as unknown as { row_version?: number }).row_version ?? job.rowVersion + 1);
        this.jobs.update(list => list.map(j => (j.id === job.id
          ? { ...j, assignedTo: userId, rowVersion: rv, start: (extra['scheduled_start'] as string) ?? j.start, end: (extra['scheduled_end'] as string) ?? j.end }
          : j)));
        done?.();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.message.set(e.status === 409 ? this.lang.translate('resourceBoard.stale') : this.lang.errorText(e));
        if (e.status === 409) this.load(this.date());
      },
    });
  }

  private load(date: string): void {
    const from = `${date}T00:00:00Z`;
    const next = new Date(Date.parse(from) + 24 * 3600 * 1000).toISOString();
    forkJoin({
      techs: this.query.execute({ entity: 'technician_profile', page: 1, page_size: 200, filters: [] }),
      jobs: this.query.execute({
        entity: 'work_order', page: 1, page_size: 200,
        filters: [{ field: 'scheduled_start', op: 'gte', value: from }, { field: 'scheduled_start', op: 'lt', value: next }],
      }),
    }).pipe(catchError((e: ApiError) => { this.message.set(this.lang.errorText(e)); return of(null); })).subscribe(res => {
      if (!res) return;
      this.technicians.set(res.techs.data.records
        .filter(r => r['user_ref'])
        .map(r => ({ profileId: String(r['id']), userId: String(r['user_ref']), name: String(r['name'] ?? r['user_ref']) })));
      this.jobs.set(res.jobs.data.records.map(r => ({
        id: String(r['id']),
        title: String(r['title'] ?? r['work_order_number'] ?? r['id']),
        start: (r['scheduled_start'] as string | null) ?? null,
        end: (r['scheduled_end'] as string | null) ?? null,
        assignedTo: (r['assigned_to'] as string | null) ?? null,
        rowVersion: Number(r['row_version'] ?? 0),
      })));
    });
  }
}
