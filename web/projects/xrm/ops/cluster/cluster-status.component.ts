import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';

/** `attome_ops::status::ClusterMember`. */
export interface ClusterMember {
  name: string;
  role: string;
  state: string | null;
  lag_bytes: number | null;
  timeline: number | null;
}

/** `attome_ops::status::FailoverEvent`. */
export interface FailoverEvent {
  id: string;
  kind: string;
  old_leader: string | null;
  new_leader: string;
  timeline: number | null;
  started_at: string;
  ended_at: string | null;
  duration_ms: number | null;
  writes_lost: number | null;
  cause: string | null;
}

/** `attome_ops::status::ClusterStatus` (`GET /api/v1/ops/cluster`). */
export interface ClusterStatus {
  mode: 'single' | 'ha';
  leader: string | null;
  members: ClusterMember[];
  synchronous_standby: string | null;
  last_failover: FailoverEvent | null;
}

interface FailoverPage {
  items: FailoverEvent[];
  total: number;
  page: number;
  page_size: number;
}

/** `attome_ops::switchover::SwitchoverApproval`. */
interface SwitchoverApproval {
  approval_id: string;
  status: string;
}

export const REASON_MIN = 10;
export const REASON_MAX = 500;
const PAGE_SIZE = 20;

/** Whether a switchover reason is long enough and not too long. */
export function reasonOk(reason: string): boolean {
  const n = reason.trim().length;
  return n >= REASON_MIN && n <= REASON_MAX;
}

/**
 * The database cluster (roadmap AB2-T11): one line on a single-server
 * deployment; with a Patroni cluster, its members (role, state, lag, the
 * synchronous standby marked) and the failover history. A holder of
 * `ops.cluster.switchover` can ask for a planned switchover, which only
 * creates the approval a second person decides.
 */
@Component({
  selector: 'attome-ops-cluster-status',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe, LocalDatePipe],
  template: `
    <section class="oc-page">
      <h2>{{ 'ops.cluster.title' | translate }}</h2>

      @if (error(); as message) {
        <p class="oc-error" role="alert">{{ message }}</p>
      }

      @if (status(); as s) {
        @if (s.mode === 'single') {
          <p class="oc-single" data-testid="oc-single">{{ 'ops.cluster.single' | translate }}</p>
        } @else {
          <p>
            {{ 'ops.cluster.leader' | translate }}:
            <strong dir="ltr">{{ s.leader ?? ('ops.cluster.noLeader' | translate) }}</strong>
          </p>
          <div class="oc-scroll">
            <table class="oc-table" data-testid="oc-members">
              <thead>
                <tr>
                  <th scope="col">{{ 'ops.cluster.member' | translate }}</th>
                  <th scope="col">{{ 'ops.cluster.role' | translate }}</th>
                  <th scope="col">{{ 'ops.cluster.state' | translate }}</th>
                  <th scope="col">{{ 'ops.cluster.lag' | translate }}</th>
                </tr>
              </thead>
              <tbody>
                @for (m of s.members; track m.name) {
                  <tr data-testid="oc-member">
                    <td dir="ltr">
                      {{ m.name }}
                      @if (m.name === s.synchronous_standby) {
                        <span class="oc-sync">{{ 'ops.cluster.sync' | translate }}</span>
                      }
                    </td>
                    <td>{{ m.role }}</td>
                    <td>{{ m.state ?? '—' }}</td>
                    <td dir="ltr">{{ m.lag_bytes === null ? '—' : m.lag_bytes }}</td>
                  </tr>
                }
              </tbody>
            </table>
          </div>

          @if (canSwitch()) {
            <button type="button" class="oc-request" data-testid="oc-request"
                    (click)="openDialog()">{{ 'ops.cluster.request' | translate }}</button>
          }
        }

        <h3>{{ 'ops.cluster.history' | translate }}</h3>
        @if (failovers().length === 0) {
          <p>{{ 'ops.cluster.noHistory' | translate }}</p>
        } @else {
          <ul class="oc-history" data-testid="oc-history">
            @for (f of failovers(); track f.id) {
              <li>
                <strong>{{ 'ops.cluster.kind.' + f.kind | translate }}</strong>
                <span dir="ltr">{{ f.old_leader ?? '—' }} → {{ f.new_leader }}</span>
                · {{ f.started_at | localDate }}
                @if (f.duration_ms !== null) {
                  · {{ 'ops.cluster.duration' | translate: { ms: f.duration_ms } }}
                }
              </li>
            }
          </ul>
          <div class="oc-pages">
            <button type="button" [disabled]="page() <= 1" (click)="loadHistory(page() - 1)">
              {{ 'ops.cluster.prev' | translate }}
            </button>
            <button type="button" [disabled]="page() * pageSize >= total()" (click)="loadHistory(page() + 1)">
              {{ 'ops.cluster.next' | translate }}
            </button>
          </div>
        }
      }

      @if (dialogOpen()) {
        <div class="oc-dialog" role="dialog" aria-modal="true"
             [attr.aria-label]="'ops.cluster.request' | translate" data-testid="oc-dialog">
          @if (approvalId(); as id) {
            <p role="status" data-testid="oc-approval">{{ 'ops.cluster.requested' | translate: { id } }}</p>
            <button type="button" (click)="closeDialog()">{{ 'ops.cluster.close' | translate }}</button>
          } @else {
            <label>
              {{ 'ops.cluster.candidate' | translate }}
              <select [(ngModel)]="candidate" name="candidate" data-testid="oc-candidate">
                <option value="">{{ 'ops.cluster.anyCandidate' | translate }}</option>
                @for (m of replicas(); track m.name) {
                  <option [value]="m.name">{{ m.name }}</option>
                }
              </select>
            </label>
            <label>
              {{ 'ops.cluster.reason' | translate }}
              <textarea [(ngModel)]="reason" name="reason" rows="3" [attr.maxlength]="reasonMax"
                        data-testid="oc-reason" dir="auto"></textarea>
            </label>
            @if (formError(); as message) {
              <p class="oc-error" role="alert" data-testid="oc-form-error">{{ message }}</p>
            }
            <div class="oc-buttons">
              <button type="button" data-testid="oc-submit" [disabled]="submitting()" (click)="submit()">
                {{ 'ops.cluster.submit' | translate }}
              </button>
              <button type="button" (click)="closeDialog()">{{ 'ops.cluster.cancel' | translate }}</button>
            </div>
          }
        </div>
      }
    </section>
  `,
  styles: [`
    .oc-page { padding-inline: 1rem; max-inline-size: 60rem; }
    .oc-scroll { overflow-x: auto; }
    .oc-table { border-collapse: collapse; inline-size: 100%; }
    .oc-table th, .oc-table td { padding-block: 0.375rem; padding-inline: 0.5rem; text-align: start; border-block-end: 1px solid var(--color-border); }
    .oc-sync { margin-inline-start: 0.5rem; font-size: 0.75rem; padding-inline: 0.375rem; border: 1px solid var(--color-border); border-radius: 0.25rem; }
    .oc-request { margin-block: 0.75rem; }
    .oc-history { padding-inline-start: 1.25rem; }
    .oc-pages { display: flex; gap: 0.5rem; }
    .oc-dialog { display: flex; flex-direction: column; gap: 0.75rem; margin-block: 1rem; padding: 1rem; border: 1px solid var(--color-border); border-radius: 0.5rem; max-inline-size: 32rem; }
    .oc-dialog label { display: flex; flex-direction: column; gap: 0.25rem; }
    .oc-buttons { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .oc-error { color: var(--color-danger); }
  `],
})
export class ClusterStatusComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly access = inject(AccessService);
  private readonly lang = inject(LangService);

  readonly status = signal<ClusterStatus | null>(null);
  readonly failovers = signal<FailoverEvent[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly pageSize = PAGE_SIZE;
  readonly error = signal<string | null>(null);
  readonly canSwitch = signal(false);
  readonly dialogOpen = signal(false);
  readonly submitting = signal(false);
  readonly approvalId = signal<string | null>(null);
  readonly formError = signal<string | null>(null);
  readonly reasonMax = REASON_MAX;

  candidate = '';
  reason = '';

  ngOnInit(): void {
    this.access.ready().subscribe(() =>
      this.canSwitch.set(this.access.hasPrivilege('ops.cluster.switchover')));
    this.api.get<ClusterStatus>('/api/v1/ops/cluster').subscribe({
      next: s => this.status.set(s),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
    this.loadHistory(1);
  }

  /** The members a switchover can promote: everyone but the leader. */
  replicas(): ClusterMember[] {
    const s = this.status();
    return s ? s.members.filter(m => m.name !== s.leader) : [];
  }

  loadHistory(page: number): void {
    this.api.get<FailoverPage>('/api/v1/ops/failovers', {
      page: String(page), page_size: String(PAGE_SIZE),
    }).subscribe({
      next: p => {
        this.failovers.set(p.items ?? []);
        this.total.set(p.total ?? 0);
        this.page.set(page);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  openDialog(): void {
    this.candidate = '';
    this.reason = '';
    this.approvalId.set(null);
    this.formError.set(null);
    this.dialogOpen.set(true);
  }

  closeDialog(): void {
    this.dialogOpen.set(false);
  }

  submit(): void {
    if (!reasonOk(this.reason)) {
      this.formError.set(this.lang.translate('ops.cluster.reasonLength', { min: REASON_MIN, max: REASON_MAX }));
      return;
    }
    this.formError.set(null);
    this.submitting.set(true);
    const body = { reason: this.reason.trim(), ...(this.candidate ? { candidate: this.candidate } : {}) };
    this.api.post<SwitchoverApproval>('/api/v1/ops/cluster/switchover', body).subscribe({
      next: res => {
        this.submitting.set(false);
        this.approvalId.set(res.approval_id);
      },
      error: (e: ApiError) => {
        this.submitting.set(false);
        this.formError.set(this.lang.errorText(e));
      },
    });
  }
}
