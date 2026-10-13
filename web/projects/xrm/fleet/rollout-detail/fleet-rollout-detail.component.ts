import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { Observable } from 'rxjs';
import { LangService, LocalDatePipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { DialogService } from '@attome/base/dialog';
import { FleetService } from '../data/fleet.service';
import { fleetErrorText } from '../data/fleet-error-text';
import { fleetLabel, type FleetLabelSet } from '../data/fleet-labels';
import type { RolloutDetail, TargetView, WaveView } from '../data/fleet.types';

/** One wave with its targets, for the page. */
export interface WaveGroup {
  index:   number;
  wave:    WaveView;
  current: boolean;
  targets: TargetView[];
}

/** Targets grouped under their wave, in wave order. */
export function groupTargets(detail: RolloutDetail): WaveGroup[] {
  return detail.rollout.waves.map((wave, index) => ({
    index,
    wave,
    current: index === detail.rollout.cursor,
    targets: detail.targets.filter(t => t.wave === index),
  }));
}

/** Only an `http(s)` approval link is offered (it comes from the registered base URL). */
export function safeApprovalUrl(url: string | null): string | null {
  if (!url) return null;
  return /^https?:\/\//i.test(url) ? url : null;
}

const MAX_BACKUP_REF = 500;

/**
 * `/xrm/fleet/rollouts/:id` (D-792 F4): one rollout — its changesets, its
 * waves and every customer in them. From here the developer applies a planned
 * customer of the current wave (with the backup taken before it; required on
 * production; a fresh step-up), skips a customer, halts, resumes (step-up),
 * cancels, or re-queues the waiting steps. A customer waiting for approval
 * shows the link to its approval page: a person approves there. The console
 * never approves.
 */
@Component({
  selector: 'attome-fleet-rollout-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, LocalDatePipe, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', '../fleet.css', './fleet-rollout-detail.component.css'],
  templateUrl: './fleet-rollout-detail.component.html',
})
export class FleetRolloutDetailComponent {
  private readonly svc = inject(FleetService);
  private readonly lang = inject(LangService);
  private readonly dialog = inject(DialogService);
  private readonly destroyRef = inject(DestroyRef);

  /** Route parameter (`withComponentInputBinding()`). */
  readonly id = input.required<string>();

  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly maxBackupRef = MAX_BACKUP_REF;

  readonly detail = signal<RolloutDetail | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly busy = signal(false);

  /** The backup reference typed in per target. */
  readonly backupRefs = signal<Record<string, string>>({});
  readonly targetErrors = signal<Record<string, string>>({});
  readonly busyTarget = signal<string | null>(null);

  readonly groups = computed(() => {
    const d = this.detail();
    return d ? groupTargets(d) : [];
  });
  readonly status = computed(() => this.detail()?.rollout.status ?? '');
  readonly canHalt = computed(() => this.status() === 'in_progress');
  readonly canResume = computed(() => this.status() === 'halted');
  readonly canCancel = computed(() => ['planned', 'in_progress', 'halted'].includes(this.status()));

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => {
        this.notice.set(null);
        this.load(id);
      });
    });
  }

  text(set: FleetLabelSet, value: string | null | undefined): string {
    return fleetLabel(this.lang, set, value);
  }

  approvalUrl(target: TargetView): string | null {
    return safeApprovalUrl(target.approval_url);
  }

  /** Only a planned customer of the current wave of a running rollout can be applied. */
  canApply(target: TargetView): boolean {
    const d = this.detail();
    return !!d && d.rollout.status === 'in_progress' && target.wave === d.rollout.cursor && target.status === 'planned';
  }

  canSkip(target: TargetView): boolean {
    return ['pending', 'planned', 'failed'].includes(target.status);
  }

  backupRefOf(targetId: string): string {
    return this.backupRefs()[targetId] ?? '';
  }

  setBackupRef(targetId: string, value: string): void {
    this.backupRefs.update(map => ({ ...map, [targetId]: value }));
  }

  /** A production customer needs the backup reference before Apply. */
  applyReady(target: TargetView): boolean {
    const ref = this.backupRefOf(target.id).trim();
    if (ref.length > MAX_BACKUP_REF) return false;
    return target.environment !== 'prod' || ref.length > 0;
  }

  targetError(targetId: string): string | null {
    return this.targetErrors()[targetId] ?? null;
  }

  reload(): void {
    this.load(this.id());
  }

  private load(id: string): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.getRollout(id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: d => {
        if (id !== this.id()) return; // a late answer for the previous rollout
        this.detail.set(d);
        this.loading.set(false);
      },
      error: (err: ApiError) => {
        if (id !== this.id()) return;
        this.error.set(fleetErrorText(this.lang, err));
        this.loading.set(false);
      },
    });
  }

  // ── Rollout actions ─────────────────────────────────────────────────────

  refreshSteps(): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.notice.set(null);
    this.error.set(null);
    this.svc.refreshRollout(this.id()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.busy.set(false);
        this.notice.set(this.lang.translate('fleet.rollout.stepsQueued', { count: res.queued }));
        this.reload();
      },
      error: (err: ApiError) => { this.busy.set(false); this.error.set(fleetErrorText(this.lang, err)); },
    });
  }

  halt(): void {
    const d = this.detail();
    if (!d || !this.canHalt()) return;
    this.transition(this.svc.haltRollout(d.rollout.id, d.rollout.row_version), 'fleet.rollout.halted');
  }

  resume(): void {
    const d = this.detail();
    if (!d || !this.canResume()) return;
    this.transition(this.svc.resumeRollout(d.rollout.id, d.rollout.row_version), 'fleet.rollout.resumed');
  }

  async cancel(): Promise<void> {
    const d = this.detail();
    if (!d || !this.canCancel() || this.busy()) return;
    const ok = await this.dialog.confirm({
      title:       this.lang.translate('fleet.rollout.cancelTitle'),
      message:     this.lang.translate('fleet.rollout.cancelConfirm'),
      confirmText: this.lang.translate('fleet.rollout.cancel'),
      cancelText:  this.lang.translate('fleet.common.keep'),
      variant:     'danger',
    });
    if (!ok) return;
    this.transition(this.svc.cancelRollout(d.rollout.id, d.rollout.row_version), 'fleet.rollout.cancelled');
  }

  private transition(request: Observable<RolloutDetail>, noticeKey: string): void {
    if (this.busy()) return;
    this.busy.set(true);
    this.notice.set(null);
    this.error.set(null);
    request.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: d => {
        this.busy.set(false);
        this.detail.set(d);
        this.notice.set(this.lang.translate(noticeKey));
      },
      error: (err: ApiError) => {
        this.busy.set(false);
        this.error.set(err.kind === 'version_conflict'
          ? this.lang.translate('fleet.rollout.versionConflict')
          : fleetErrorText(this.lang, err));
        if (err.kind === 'version_conflict') this.reload();
      },
    });
  }

  // ── Target actions ──────────────────────────────────────────────────────

  apply(target: TargetView): void {
    const d = this.detail();
    if (!d || !this.canApply(target) || !this.applyReady(target) || this.busyTarget()) return;
    const ref = this.backupRefOf(target.id).trim();
    this.busyTarget.set(target.id);
    this.clearTargetError(target.id);
    this.notice.set(null);
    this.svc.applyTarget(d.rollout.id, target.id, { row_version: target.row_version, backup_ref: ref || null })
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: updated => {
          this.busyTarget.set(null);
          this.replaceTarget(updated);
          this.notice.set(this.lang.translate(
            updated.status === 'approval_pending' ? 'fleet.rollout.sentForApproval' : 'fleet.rollout.applying',
            { name: updated.deployment_label },
          ));
        },
        error: (err: ApiError) => this.targetFailed(target, err),
      });
  }

  async skip(target: TargetView): Promise<void> {
    const d = this.detail();
    if (!d || !this.canSkip(target) || this.busyTarget()) return;
    const ok = await this.dialog.confirm({
      title:       this.lang.translate('fleet.rollout.skipTitle'),
      message:     this.lang.translate('fleet.rollout.skipConfirm', { name: target.deployment_label }),
      confirmText: this.lang.translate('fleet.rollout.skip'),
      cancelText:  this.lang.translate('fleet.common.keep'),
      variant:     'warning',
    });
    if (!ok) return;
    this.busyTarget.set(target.id);
    this.clearTargetError(target.id);
    this.svc.skipTarget(d.rollout.id, target.id, target.row_version)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: updated => {
          this.busyTarget.set(null);
          this.replaceTarget(updated);
          // Skipping can complete the wave and start the next one.
          this.reload();
        },
        error: (err: ApiError) => this.targetFailed(target, err),
      });
  }

  private replaceTarget(updated: TargetView): void {
    this.detail.update(d => d && { ...d, targets: d.targets.map(t => (t.id === updated.id ? updated : t)) });
  }

  private targetFailed(target: TargetView, err: ApiError): void {
    this.busyTarget.set(null);
    const text = err.kind === 'version_conflict'
      ? this.lang.translate('fleet.rollout.versionConflict')
      : fleetErrorText(this.lang, err);
    this.targetErrors.update(map => ({ ...map, [target.id]: text }));
    // A refused apply leaves the target planned with its error code; show it.
    this.reload();
  }

  private clearTargetError(targetId: string): void {
    this.targetErrors.update(map => {
      const next = { ...map };
      delete next[targetId];
      return next;
    });
  }
}
