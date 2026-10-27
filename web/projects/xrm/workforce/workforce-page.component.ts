import { ChangeDetectionStrategy, Component, computed, inject, OnInit, signal } from '@angular/core';
import { ApiError, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { forkJoin } from 'rxjs';
import { ScheduleGridComponent } from './schedule-grid/schedule-grid.component';
import {
  AssignmentView, LiveRow, OfferRow, PickOption, ScheduleDetail, ScheduleSummary, SwapRow, WorkforceApiService,
} from './workforce-api.service';

export type WorkforceTab = 'schedules' | 'swaps' | 'intraday' | 'adherence';

/** The message for a failed write: a 409 is "changed since you loaded it". Pure. */
export function writeErrorKey(error: Pick<ApiError, 'status'> | null | undefined): string | null {
  if (!error) return null;
  return error.status === 409 ? 'xrm.workforce.conflict' : null;
}

/**
 * G17-T13: the workforce screens. Planners pick a planning group, build a
 * draft schedule for a period, look at it as a grid with its coverage, move
 * an assignment (to another person) and publish it; a write that lost a race
 * says so and asks to reload. Swaps waiting for a planner, intraday
 * proposals waiting to be sent and the group's live adherence are the other
 * tabs. Labels are in Arabic and English; dates show Hijri beside Gregorian.
 */
@Component({
  selector: 'xrm-workforce-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, ScheduleGridComponent, TranslatePipe],
  templateUrl: './workforce-page.component.html',
  styleUrl: './workforce-page.component.css',
})
export class WorkforcePageComponent implements OnInit {
  private readonly api = inject(WorkforceApiService);
  private readonly lang = inject(LangService);

  readonly tabs: readonly WorkforceTab[] = ['schedules', 'swaps', 'intraday', 'adherence'];
  readonly tab = signal<WorkforceTab>('schedules');

  readonly groups = signal<PickOption[]>([]);
  readonly users = signal<PickOption[]>([]);
  readonly group = signal<string>('');
  readonly schedules = signal<ScheduleSummary[]>([]);
  readonly detail = signal<ScheduleDetail | null>(null);
  readonly swaps = signal<SwapRow[]>([]);
  readonly proposals = signal<OfferRow[]>([]);
  readonly live = signal<LiveRow[]>([]);

  readonly buildFrom = signal('');
  readonly buildTo = signal('');
  readonly editing = signal<AssignmentView | null>(null);
  readonly moveTo = signal('');
  readonly confirmPublish = signal(false);

  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  private readonly names = computed(() => new Map(this.users().map(u => [u.id, u.label])));
  readonly isDraft = computed(() => this.detail()?.status === 'draft');
  readonly inAdherence = computed(() => this.live().filter(r => r.in_adherence).length);

  ngOnInit(): void {
    forkJoin({ groups: this.api.groups(), users: this.api.users() }).subscribe({
      next: r => {
        this.groups.set(r.groups);
        this.users.set(r.users);
        if (r.groups[0]) this.pickGroup(r.groups[0].id);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  tabKey(tab: WorkforceTab): string {
    switch (tab) {
      case 'swaps': return 'xrm.workforce.tabs.swaps';
      case 'intraday': return 'xrm.workforce.tabs.intraday';
      case 'adherence': return 'xrm.workforce.tabs.adherence';
      default: return 'xrm.workforce.tabs.schedules';
    }
  }

  userName(id: string | null | undefined): string {
    return (id && this.names().get(id)) ?? id ?? '';
  }

  pickTab(tab: WorkforceTab): void {
    this.tab.set(tab);
    this.error.set(null);
    if (tab === 'swaps') this.api.swaps().subscribe({ next: s => this.swaps.set(s), error: (e: ApiError) => this.fail(e) });
    if (tab === 'intraday') this.api.proposals().subscribe({ next: p => this.proposals.set(p), error: (e: ApiError) => this.fail(e) });
    if (tab === 'adherence' && this.group()) {
      this.api.live(this.group()).subscribe({ next: l => this.live.set(l), error: (e: ApiError) => this.fail(e) });
    }
  }

  pickGroup(id: string): void {
    this.group.set(id);
    this.detail.set(null);
    this.api.schedules(id).subscribe({ next: s => this.schedules.set(s), error: (e: ApiError) => this.fail(e) });
  }

  open(id: string): void {
    this.confirmPublish.set(false);
    this.editing.set(null);
    this.api.schedule(id).subscribe({ next: d => this.detail.set(d), error: (e: ApiError) => this.fail(e) });
  }

  build(): void {
    const group = this.group();
    if (!group || !this.buildFrom() || !this.buildTo()) {
      this.error.set(this.lang.translate('xrm.workforce.buildNeedsDates'));
      return;
    }
    this.run(this.api.build(group, this.buildFrom(), this.buildTo()), () => {
      this.notice.set(this.lang.translate('xrm.workforce.buildQueued'));
      this.pickGroup(group);
    });
  }

  publish(): void {
    const d = this.detail();
    if (!d) return;
    if (!this.confirmPublish()) {
      this.confirmPublish.set(true);
      return;
    }
    this.confirmPublish.set(false);
    this.run(this.api.publish(d.id, d.row_version), () => {
      this.notice.set(this.lang.translate('xrm.workforce.published'));
      this.open(d.id);
    });
  }

  edit(assignment: AssignmentView): void {
    this.editing.set(assignment);
    this.moveTo.set(assignment.user_id ?? '');
  }

  saveMove(): void {
    const a = this.editing();
    const d = this.detail();
    if (!a || !d || !this.moveTo()) return;
    this.run(this.api.moveAssignment(a.id, a.row_version, { user_id: this.moveTo() }), () => {
      this.editing.set(null);
      this.open(d.id);
    });
  }

  decide(swap: SwapRow, approve: boolean): void {
    this.run(this.api.decideSwap(swap.id, approve, null), () => this.pickTab('swaps'));
  }

  send(offer: OfferRow): void {
    this.run(this.api.sendOffer(offer.id), () => this.pickTab('intraday'));
  }

  private run(call: ReturnType<WorkforceApiService['sendOffer']>, done: () => void): void {
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
    call.subscribe({
      next: () => {
        this.busy.set(false);
        done();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.fail(e);
      },
    });
  }

  private fail(e: ApiError): void {
    const key = writeErrorKey(e);
    this.error.set(key ? this.lang.translate(key) : this.lang.errorText(e) || null);
  }
}
