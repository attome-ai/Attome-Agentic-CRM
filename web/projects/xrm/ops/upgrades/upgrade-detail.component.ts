import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import { RouterLink } from '@angular/router';
import { LocalDatePipe, TranslatePipe } from '@attome/base';

/** `attome_ops::upgrade_check::Finding`. */
export interface UpgradeFinding {
  check: string;
  verdict: 'pass' | 'warn' | 'fail';
  detail: string;
}

/** `attome_ops::release_manifest::Impact`: what a release changes for one module. */
export interface UpgradeImpact {
  module: string;
  en: string;
  ar: string;
}

/**
 * The upgrade rehearsal's result (AB8-T4), when `upgrade rehearse` recorded
 * one into the check report. Every part is optional: a report written before
 * the rehearsal existed has none.
 */
export interface UpgradeRehearsal {
  schema_changes?: string[];
  conflicts?: { kind?: string; object?: string; detail?: string }[];
  customer_tests?: { passed?: number; failed?: number; failures?: string[] };
  old_binary?: { ok: boolean; detail?: string };
}

/**
 * `ops_upgrade.check_report`: the pre-upgrade check's report
 * (`attome_ops::upgrade_check::Report`) as `attome upgrade apply` stores it,
 * with the previous binary, the release's impact items (AB8-T8) and the
 * contract steps done.
 */
export interface UpgradeCheckReport {
  from_version?: string;
  to_version?: string;
  requires_pause?: boolean;
  pause_estimate_seconds?: number | null;
  findings?: UpgradeFinding[];
  previous_binary?: string;
  impact?: UpgradeImpact[];
  rehearsal?: UpgradeRehearsal;
  contract_done?: string[];
}

/** `attome_ops::upgrades::Upgrade`. */
export interface Upgrade {
  id: string;
  from_version: string | null;
  to_version: string | null;
  started_by: string | null;
  started_at: string | null;
  finished_at: string | null;
  status: 'started' | 'verified' | 'failed' | 'rolled_back';
  safety_point: string | null;
  check_report: UpgradeCheckReport | null;
  verification_evidence_id: string | null;
  contract_applied_at: string | null;
  row_version: number;
}

/** What the rollback can still do for an upgrade. */
export type RollbackState = 'done' | 'closed' | 'open' | 'none';

/**
 * Rolled back already; closed once the contract step removed the old schema
 * (the old binary can no longer run on it); open while the previous binary
 * is recorded; else none.
 */
export function rollbackState(upgrade: Upgrade): RollbackState {
  if (upgrade.status === 'rolled_back') return 'done';
  if (upgrade.contract_applied_at) return 'closed';
  if (upgrade.check_report?.previous_binary) return 'open';
  return 'none';
}

/**
 * The impact items of the modules switched on, in the given language
 * (`ar`, else English). A module named `platform` (or with no name) applies
 * to every deployment and is always kept.
 */
export function activeImpact(
  items: readonly UpgradeImpact[] | undefined,
  enabledModules: ReadonlySet<string>,
  lang: string,
): { module: string; text: string }[] {
  return (items ?? [])
    .filter(i => !i.module || i.module === 'platform' || enabledModules.has(i.module))
    .map(i => ({ module: i.module, text: (lang === 'ar' ? i.ar : i.en) || i.en || i.ar }));
}

/**
 * One upgrade (roadmap AB8-T8): the check results, the linked verification
 * evidence, the rehearsal's impact (schema changes, conflicts, customer
 * tests, the old-binary run), what changes for this deployment and the
 * rollback status.
 */
@Component({
  selector: 'attome-ops-upgrade-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe, LocalDatePipe],
  template: `
    @let u = upgrade();
    <article class="ud" data-testid="ud">
      <h3>
        <span dir="ltr">{{ u.from_version ?? '—' }} → {{ u.to_version ?? '—' }}</span>
        · {{ 'ops.upgrades.status.' + u.status | translate }}
      </h3>
      <dl class="ud-facts">
        <dt>{{ 'ops.upgrades.started' | translate }}</dt>
        <dd>{{ u.started_at ? (u.started_at | localDate) : '—' }}</dd>
        <dt>{{ 'ops.upgrades.finished' | translate }}</dt>
        <dd>{{ u.finished_at ? (u.finished_at | localDate) : '—' }}</dd>
        <dt>{{ 'ops.upgrades.safetyPoint' | translate }}</dt>
        <dd dir="ltr">{{ u.safety_point ?? '—' }}</dd>
        <dt>{{ 'ops.upgrades.rollback' | translate }}</dt>
        <dd data-testid="ud-rollback">{{ 'ops.upgrades.rollbackState.' + rollback() | translate }}</dd>
        <dt>{{ 'ops.upgrades.evidence' | translate }}</dt>
        <dd>
          @if (u.verification_evidence_id) {
            <a [routerLink]="['/xrm/ops/drills', u.verification_evidence_id]" data-testid="ud-evidence">
              {{ 'ops.upgrades.openEvidence' | translate }}
            </a>
          } @else {
            {{ 'ops.upgrades.noEvidence' | translate }}
          }
        </dd>
      </dl>

      <h4>{{ 'ops.upgrades.checks' | translate }}</h4>
      @if (findings().length > 0) {
        <ul class="ud-findings">
          @for (f of findings(); track f.check) {
            <li [attr.data-verdict]="f.verdict" data-testid="ud-finding">
              <strong>{{ 'ops.upgrades.verdict.' + f.verdict | translate }}</strong>
              <span dir="ltr">{{ f.check }}</span>
              @if (f.detail) { <span class="ud-detail">{{ f.detail }}</span> }
            </li>
          }
        </ul>
      } @else {
        <p>{{ 'ops.upgrades.noChecks' | translate }}</p>
      }

      <h4>{{ 'ops.upgrades.rehearsal' | translate }}</h4>
      @if (rehearsal(); as r) {
        @if (r.old_binary; as old) {
          <p data-testid="ud-old-binary" [attr.data-ok]="old.ok">
            {{ (old.ok ? 'ops.upgrades.oldBinaryOk' : 'ops.upgrades.oldBinaryFailed') | translate }}
            @if (old.detail) { · <span class="ud-detail">{{ old.detail }}</span> }
          </p>
        }
        @if (r.customer_tests; as t) {
          <p data-testid="ud-customer-tests">
            {{ 'ops.upgrades.customerTests' | translate }}:
            {{ t.passed ?? 0 }} {{ 'ops.upgrades.passed' | translate }},
            {{ t.failed ?? 0 }} {{ 'ops.upgrades.failed' | translate }}
          </p>
          @if (t.failures?.length) {
            <ul class="ud-list">
              @for (name of t.failures; track name) { <li dir="ltr">{{ name }}</li> }
            </ul>
          }
        }
        @if (r.schema_changes?.length) {
          <h5>{{ 'ops.upgrades.schemaChanges' | translate }}</h5>
          <ul class="ud-list">
            @for (c of r.schema_changes; track $index) { <li dir="ltr">{{ c }}</li> }
          </ul>
        }
        @if (r.conflicts?.length) {
          <h5>{{ 'ops.upgrades.conflicts' | translate }}</h5>
          <ul class="ud-list" data-testid="ud-conflicts">
            @for (c of r.conflicts; track $index) {
              <li><span dir="ltr">{{ c.object ?? c.kind ?? '—' }}</span>@if (c.detail) { · {{ c.detail }} }</li>
            }
          </ul>
        }
      } @else {
        <p>{{ 'ops.upgrades.noRehearsal' | translate }}</p>
      }

      <h4>{{ 'ops.upgrades.forYou' | translate }}</h4>
      @if (impact().length > 0) {
        <ul class="ud-list" data-testid="ud-impact">
          @for (i of impact(); track $index) {
            <li data-testid="ud-impact-item">
              <strong>{{ i.module ? ('ops.upgrades.module' | translate) + ' ' + i.module : ('ops.upgrades.platform' | translate) }}</strong>:
              {{ i.text }}
            </li>
          }
        </ul>
      } @else {
        <p>{{ 'ops.upgrades.noImpact' | translate }}</p>
      }
    </article>
  `,
  styles: [`
    .ud { padding-block: 0.5rem; }
    .ud-facts { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; }
    .ud-facts dt { font-weight: 600; }
    .ud-facts dd { margin: 0; }
    .ud-findings { padding: 0; list-style: none; display: flex; flex-direction: column; gap: 0.25rem; }
    .ud-findings li { display: flex; flex-wrap: wrap; gap: 0.5rem; padding-inline-start: 0.5rem; border-inline-start: 4px solid var(--color-success); }
    .ud-findings li[data-verdict='warn'] { border-inline-start-color: var(--color-warning); }
    .ud-findings li[data-verdict='fail'] { border-inline-start-color: var(--color-danger); }
    .ud-detail { color: var(--color-text-muted); }
    .ud-list { padding-inline-start: 1.25rem; }
    [data-ok='false'] { color: var(--color-danger); }
  `],
})
export class UpgradeDetailComponent {
  readonly upgrade = input.required<Upgrade>();
  /** The modules switched on on this deployment. */
  readonly enabledModules = input<ReadonlySet<string>>(new Set());
  /** The user's language (`en` or `ar`). */
  readonly lang = input<string>('en');

  readonly findings = computed(() => this.upgrade().check_report?.findings ?? []);
  readonly rehearsal = computed(() => this.upgrade().check_report?.rehearsal ?? null);
  readonly rollback = computed(() => rollbackState(this.upgrade()));
  readonly impact = computed(() =>
    activeImpact(this.upgrade().check_report?.impact, this.enabledModules(), this.lang()));
}
