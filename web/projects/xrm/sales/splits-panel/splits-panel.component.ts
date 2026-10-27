import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { forkJoin } from 'rxjs';
import { SalesApiService } from '../sales-api.service';
import { PickOption, SalesTeamApiService, SplitRow, SplitType, TeamMember } from '../team-api';

/** The feature that turns splits on. */
export const SPLITS_FLAG = 'sales.splits';

function num(text: string | null | undefined): number {
  const n = Number.parseFloat((text ?? '').trim());
  return Number.isFinite(n) ? n : 0;
}

/** Each split type's total percent over `rows` (whole-deal and per-line splits apart). Pure. */
export function typeTotals(rows: readonly SplitRow[]): Map<string, number> {
  const totals = new Map<string, number>();
  for (const r of rows) {
    const key = `${r.split_type_ref}|${r.line_ref ?? ''}`;
    totals.set(key, (totals.get(key) ?? 0) + num(r.percent));
  }
  return totals;
}

/**
 * The split types that must total 100 (revenue types) but do not, for the
 * whole deal or one line. A type with no splits is not checked. Pure.
 */
export function unbalancedTypes(rows: readonly SplitRow[], types: readonly SplitType[]): string[] {
  const must = new Set(types.filter(t => t.must_total_100).map(t => t.id));
  const out = new Set<string>();
  for (const [key, total] of typeTotals(rows)) {
    const type = key.split('|')[0];
    if (must.has(type) && Math.abs(total - 100) > 0.005) out.add(type);
  }
  return [...out];
}

/**
 * D7-T7: an opportunity's splits, as its Splits tab. Each split credits a
 * team member a percent of one split type, for the whole deal or one line;
 * the total per type shows as it is typed and a revenue type (one that must
 * total 100) cannot be saved off 100. A won deal's change needs a reason and
 * waits on an approval. Amounts show only when the server sends them (field
 * security can hide `amount`).
 */
@Component({
  selector: 'xrm-sales-splits-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  templateUrl: './splits-panel.component.html',
  styleUrl: './splits-panel.component.css',
})
export class SplitsPanelComponent {
  private readonly sales = inject(SalesApiService);
  private readonly team = inject(SalesTeamApiService);
  private readonly lang = inject(LangService);

  readonly entityName = input('opportunity');
  readonly recordId = input<string | null>(null);

  readonly on = signal<boolean | null>(null);
  readonly rows = signal<SplitRow[]>([]);
  readonly types = signal<SplitType[]>([]);
  readonly members = signal<TeamMember[]>([]);
  readonly users = signal<PickOption[]>([]);
  readonly won = signal(false);
  readonly reason = signal('');
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly busy = signal(false);

  /** Whether the server sent amounts (field security may omit them). */
  readonly showAmount = computed(() => this.rows().some(r => r.amount !== undefined));

  readonly totals = computed(() => {
    const totals = typeTotals(this.rows().filter(r => r.line_ref === null));
    return this.types()
      .filter(t => totals.has(`${t.id}|`))
      .map(t => ({ type: t, total: totals.get(`${t.id}|`) ?? 0 }));
  });

  readonly unbalanced = computed(() => unbalancedTypes(this.rows(), this.types()));

  private readonly userNames = computed(() => new Map(this.users().map(u => [u.id, u.label])));

  constructor() {
    effect(() => {
      const id = this.recordId();
      if (id) this.load(id);
    });
  }

  private load(id: string): void {
    this.sales.featureOn(SPLITS_FLAG).subscribe({
      next: on => {
        this.on.set(on);
        if (on) this.reload(id);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e) || null),
    });
  }

  private reload(id: string): void {
    forkJoin({
      rows: this.team.splits(id),
      types: this.team.splitTypes(),
      members: this.team.members(id),
      users: this.team.users(),
      deal: this.sales.opportunity(id),
    }).subscribe({
      next: r => {
        this.rows.set(r.rows);
        this.types.set(r.types);
        this.members.set(r.members);
        this.users.set(r.users);
        this.won.set(r.deal.data['stage'] === 'closed_won');
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e) || null),
    });
  }

  memberLabel(memberId: string): string {
    const m = this.members().find(x => x.id === memberId);
    return (m?.user_ref && this.userNames().get(m.user_ref)) ?? m?.user_ref ?? m?.partner_contact_ref ?? memberId;
  }

  typeName(typeId: string): string {
    return this.types().find(t => t.id === typeId)?.name ?? typeId;
  }

  isUnbalanced(typeId: string): boolean {
    return this.unbalanced().includes(typeId);
  }

  addRow(): void {
    const member = this.members()[0];
    const type = this.types()[0];
    if (!member || !type) return;
    this.rows.update(rows => [
      ...rows,
      { member_ref: member.id, split_type_ref: type.id, line_ref: null, percent: '' },
    ]);
  }

  removeRow(index: number): void {
    this.rows.update(rows => rows.filter((_, i) => i !== index));
  }

  setRow(index: number, patch: Partial<SplitRow>): void {
    this.rows.update(rows => rows.map((r, i) => (i === index ? { ...r, ...patch } : r)));
  }

  save(): void {
    const id = this.recordId();
    if (!id) return;
    if (this.unbalanced().length > 0) {
      this.error.set(this.lang.translate('xrm.sales.splits.mustTotal'));
      return;
    }
    const reason = this.reason().trim();
    if (this.won() && !reason) {
      this.error.set(this.lang.translate('xrm.sales.splits.reasonNeeded'));
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    this.notice.set(null);
    this.team.saveSplits(id, this.rows(), this.won() ? reason : null).subscribe({
      next: out => {
        this.busy.set(false);
        if (out.approval_request_id) {
          this.notice.set(this.lang.translate('xrm.sales.splits.pendingApproval'));
        } else {
          this.notice.set(this.lang.translate('xrm.sales.splits.saved'));
          this.reload(id);
        }
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e) || null);
      },
    });
  }
}
