import { DecimalPipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, ATTOME_CONFIG, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';

/** `attome_ops::recovery_targets::RecoveryTarget`. */
export interface RecoveryTarget {
  id: string;
  profile: string;
  scenario: string;
  rpo_seconds: number;
  rto_seconds: number;
  evidence_kind: string;
  proven: boolean;
  proven_on: string | null;
  measured_rpo_seconds: number | null;
  measured_rto_seconds: number | null;
  row_version: number;
}

/** `attome_ops::live_rpo::RpoSource`. */
export interface RpoSource {
  source: string;
  value_seconds: number | null;
  target_seconds: number | null;
  status: 'ok' | 'over' | 'off';
}

/** `attome_ops::disasters::Disaster`. */
export interface Disaster {
  id: string;
  declared_by: string;
  declared_at: string;
  scenario: string;
  summary: string;
  closed_at: string | null;
  row_version: number;
}

/** `attome_ops::disasters::DisasterApproval`. */
export interface DisasterAction {
  approval_id: string;
  status: string;
  action: string | null;
  disaster_id: string | null;
}

interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export const SCENARIOS = ['node_loss', 'site_loss', 'corruption', 'ransomware', 'bad_change'] as const;
export const ACTIONS = ['switch_site', 'replace_live_data', 'failback'] as const;

/**
 * Disaster recovery (roadmap AB3-T10): this profile's recovery targets with
 * the API's proven flag, the live recovery point per source, the runbook in
 * both languages, and, for `ops.dr.declare`, declaring a disaster and asking
 * for its actions, each of which waits for a second person's approval.
 */
@Component({
  selector: 'attome-ops-recovery',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DecimalPipe, FormsModule, TranslatePipe, LocalDatePipe],
  template: `
    <section class="rc-page">
      <h2>{{ 'ops.recovery.title' | translate }}</h2>
      @if (error(); as message) {
        <p class="rc-error" role="alert">{{ message }}</p>
      }

      <h3>{{ 'ops.recovery.targets' | translate }}</h3>
      <div class="rc-scroll">
        <table class="rc-table" data-testid="rc-targets">
          <thead>
            <tr>
              <th scope="col">{{ 'ops.recovery.scenario' | translate }}</th>
              <th scope="col">{{ 'ops.recovery.rpo' | translate }}</th>
              <th scope="col">{{ 'ops.recovery.rto' | translate }}</th>
              <th scope="col">{{ 'ops.recovery.proof' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (t of targets(); track t.id) {
              <tr data-testid="rc-target">
                <td>{{ 'ops.recovery.scenarios.' + t.scenario | translate }}</td>
                <td dir="ltr">{{ t.rpo_seconds }}</td>
                <td dir="ltr">{{ t.rto_seconds }}</td>
                <td>
                  @if (t.proven) {
                    <span class="rc-proven" data-testid="rc-proven">{{ 'ops.recovery.proven' | translate }}</span>
                    @if (t.proven_on) { · {{ t.proven_on | localDate }} }
                  } @else {
                    <span class="rc-unproven" data-testid="rc-unproven">{{ 'ops.recovery.notProven' | translate }}</span>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      </div>

      <h3>{{ 'ops.recovery.liveRpo' | translate }}</h3>
      <ul class="rc-tiles">
        @for (s of rpo(); track s.source) {
          <li class="rc-tile" [attr.data-status]="s.status" data-testid="rc-rpo">
            <strong>{{ 'ops.recovery.sources.' + s.source | translate }}</strong>
            <span dir="ltr">{{ s.value_seconds === null ? '—' : (s.value_seconds | number: '1.0-0') }}</span>
            <span>{{ 'ops.recovery.status.' + s.status | translate }}</span>
            @if (s.target_seconds !== null) {
              <span class="rc-target">{{ 'ops.recovery.target' | translate }} <span dir="ltr">{{ s.target_seconds }}</span></span>
            }
          </li>
        }
      </ul>

      <h3>{{ 'ops.recovery.runbook' | translate }}</h3>
      <p class="rc-links">
        <a [href]="runbookUrl('en')" target="_blank" rel="noopener" data-testid="rc-runbook-en">{{ 'ops.recovery.runbookEn' | translate }}</a>
        <a [href]="runbookUrl('ar')" target="_blank" rel="noopener" data-testid="rc-runbook-ar">{{ 'ops.recovery.runbookAr' | translate }}</a>
      </p>

      <h3>{{ 'ops.recovery.disasters' | translate }}</h3>
      @if (canDeclare()) {
        <button type="button" data-testid="rc-declare" (click)="openDeclare()">{{ 'ops.recovery.declare' | translate }}</button>
      }
      @if (declaring()) {
        <div class="rc-dialog" role="dialog" aria-modal="true" [attr.aria-label]="'ops.recovery.declare' | translate" data-testid="rc-dialog">
          <label>
            {{ 'ops.recovery.scenario' | translate }}
            <select [(ngModel)]="scenario" name="scenario">
              @for (s of scenarios; track s) {
                <option [value]="s">{{ 'ops.recovery.scenarios.' + s | translate }}</option>
              }
            </select>
          </label>
          <label>
            {{ 'ops.recovery.summary' | translate }}
            <textarea [(ngModel)]="summary" name="summary" rows="3" dir="auto" data-testid="rc-summary"></textarea>
          </label>
          @if (formError(); as message) {
            <p class="rc-error" role="alert" data-testid="rc-form-error">{{ message }}</p>
          }
          <div class="rc-buttons">
            <button type="button" data-testid="rc-declare-submit" [disabled]="busy()" (click)="declare()">{{ 'ops.recovery.declareSubmit' | translate }}</button>
            <button type="button" (click)="declaring.set(false)">{{ 'ops.recovery.cancel' | translate }}</button>
          </div>
        </div>
      }
      <ul class="rc-disasters">
        @for (d of disasters(); track d.id) {
          <li data-testid="rc-disaster">
            <strong>{{ 'ops.recovery.scenarios.' + d.scenario | translate }}</strong>
            · {{ d.declared_at | localDate }}
            @if (d.closed_at) { · {{ 'ops.recovery.closed' | translate }} }
            <p dir="auto">{{ d.summary }}</p>
            <ul class="rc-actions">
              @for (a of actionsOf(d.id); track a.approval_id) {
                <li>{{ 'ops.recovery.actions.' + (a.action ?? 'unknown') | translate }} · {{ 'ops.recovery.approval.' + a.status | translate }}</li>
              }
            </ul>
            @if (!d.closed_at && canDeclare()) {
              <div class="rc-buttons">
                @for (a of actionNames; track a) {
                  <button type="button" [disabled]="busy()" (click)="requestAction(d, a)">{{ 'ops.recovery.actions.' + a | translate }}</button>
                }
              </div>
            }
          </li>
        } @empty {
          <li>{{ 'ops.recovery.noDisasters' | translate }}</li>
        }
      </ul>
    </section>
  `,
  styles: [`
    .rc-page { padding-inline: 1rem; max-inline-size: 64rem; }
    .rc-scroll { overflow-x: auto; }
    .rc-table { border-collapse: collapse; inline-size: 100%; }
    .rc-table th, .rc-table td { padding-block: 0.375rem; padding-inline: 0.5rem; text-align: start; border-block-end: 1px solid var(--color-border); }
    .rc-proven { color: var(--color-success); font-weight: 600; }
    .rc-unproven { color: var(--color-text-secondary); }
    .rc-tiles { display: flex; flex-wrap: wrap; gap: 0.5rem; padding: 0; list-style: none; }
    .rc-tile { display: flex; flex-direction: column; gap: 0.125rem; min-inline-size: 9rem; padding-block: 0.5rem; padding-inline: 0.75rem; border: 1px solid var(--color-border); border-radius: 0.5rem; }
    .rc-tile[data-status='ok'] { border-inline-start: 4px solid var(--color-success); }
    .rc-tile[data-status='over'] { border-inline-start: 4px solid var(--color-danger); }
    .rc-tile[data-status='off'] { border-inline-start: 4px solid var(--color-border); }
    .rc-target { font-size: 0.75rem; }
    .rc-links { display: flex; gap: 1rem; flex-wrap: wrap; }
    .rc-dialog { display: flex; flex-direction: column; gap: 0.75rem; margin-block: 1rem; padding: 1rem; border: 1px solid var(--color-border); border-radius: 0.5rem; max-inline-size: 32rem; }
    .rc-dialog label { display: flex; flex-direction: column; gap: 0.25rem; }
    .rc-buttons { display: flex; gap: 0.5rem; flex-wrap: wrap; }
    .rc-disasters { padding-inline-start: 0; list-style: none; }
    .rc-disasters > li { padding-block: 0.5rem; border-block-end: 1px solid var(--color-border); }
    .rc-actions { padding-inline-start: 1.25rem; }
    .rc-error { color: var(--color-danger); }
  `],
})
export class RecoveryComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly access = inject(AccessService);
  private readonly lang = inject(LangService);
  private readonly config = inject(ATTOME_CONFIG);

  readonly targets = signal<RecoveryTarget[]>([]);
  readonly rpo = signal<RpoSource[]>([]);
  readonly disasters = signal<Disaster[]>([]);
  readonly actions = signal<Record<string, DisasterAction[]>>({});
  readonly error = signal<string | null>(null);
  readonly canDeclare = signal(false);
  readonly declaring = signal(false);
  readonly busy = signal(false);
  readonly formError = signal<string | null>(null);
  readonly scenarios = SCENARIOS;
  readonly actionNames = ACTIONS;

  scenario: string = SCENARIOS[1];
  summary = '';

  ngOnInit(): void {
    this.access.ready().subscribe(() => this.canDeclare.set(this.access.hasPrivilege('ops.dr.declare')));
    this.api.get<Page<RecoveryTarget>>('/api/v1/ops/recovery-targets').subscribe({
      next: p => this.targets.set(p.items ?? []),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
    this.api.get<Page<RpoSource>>('/api/v1/ops/rpo').subscribe({
      next: p => this.rpo.set(p.items ?? []),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
    this.loadDisasters();
  }

  runbookUrl(lang: 'en' | 'ar'): string {
    return `${this.config.apiUrl}/api/v1/ops/dr-runbook?lang=${lang}`;
  }

  actionsOf(id: string): DisasterAction[] {
    return this.actions()[id] ?? [];
  }

  private loadDisasters(): void {
    this.api.get<Page<Disaster>>('/api/v1/ops/disasters').subscribe({
      next: p => {
        const items = p.items ?? [];
        this.disasters.set(items);
        for (const d of items) this.loadActions(d.id);
      },
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  private loadActions(id: string): void {
    this.api.get<Page<DisasterAction>>(`/api/v1/ops/disasters/${id}/actions`).subscribe({
      next: p => this.actions.update(all => ({ ...all, [id]: p.items ?? [] })),
      error: (e: ApiError) => this.error.set(this.lang.errorText(e)),
    });
  }

  openDeclare(): void {
    this.summary = '';
    this.formError.set(null);
    this.declaring.set(true);
  }

  declare(): void {
    if (this.summary.trim() === '') {
      this.formError.set(this.lang.translate('ops.recovery.summaryRequired'));
      return;
    }
    this.busy.set(true);
    this.api.post<Disaster>('/api/v1/ops/disasters', { scenario: this.scenario, summary: this.summary.trim() }).subscribe({
      next: () => {
        this.busy.set(false);
        this.declaring.set(false);
        this.loadDisasters();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.formError.set(this.lang.errorText(e));
      },
    });
  }

  /** Asks for an action; it waits for a second person's approval. */
  requestAction(d: Disaster, action: string): void {
    this.busy.set(true);
    this.api.post<DisasterAction>(`/api/v1/ops/disasters/${d.id}/actions`, { action }).subscribe({
      next: () => {
        this.busy.set(false);
        this.loadActions(d.id);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
