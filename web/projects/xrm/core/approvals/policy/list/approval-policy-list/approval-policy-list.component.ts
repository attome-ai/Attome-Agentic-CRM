import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { DatePipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiError } from '@attome/base';

import {
  ApprovalPolicy, ApprovalStep, OnTimeout, StepMode, ApprovalsAdminService,
} from '../../../services/approvals-admin.service';

/** One editable step row in the form below — string fields for the two
 *  numeric inputs so an empty box doesn't have to fight `ngModel`'s number
 *  coercion; converted to `ApprovalStep` in `buildPlan()`. */
interface StepDraft {
  mode:        StepMode;
  threshold:   string;
  approvers:   string; // comma-separated tokens, e.g. "user:<uuid>, role:<uuid>"
  sla_minutes: string;
  on_timeout:  OnTimeout;
}

function emptyStep(): StepDraft {
  return { mode: 'any', threshold: '', approvers: '', sla_minutes: '', on_timeout: 'escalate' };
}

/**
 * D-421 / M10 (Approval & Governance) — the policy editor named in this
 * module's checklist. Lists every `approval_policy` row and lets an
 * admin create/edit one's plan through a small structured step builder
 * (mode/threshold/approvers/SLA/on_timeout per step) rather than a raw JSON
 * textarea — `approvers` stays free-text (comma-separated tokens) because
 * only `"user:<uuid>"`/`"role:<uuid>"` resolve today
 * (`attome_audit::approval::validate_approver_token`); the server rejects an
 * unsupported token shape at save time, and any validation error message is
 * surfaced as-is.
 *
 * Same conventions as `approval-queue-list.component.ts`: inline template
 * would be file-local, but this one is expressed as separate `.html`/`.css`
 * files to match the sibling component's own layout; signals + `ApiService`
 * error-kind contract throughout.
 */
@Component({
  selector:   'xrm-approval-policy-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:    [DatePipe, FormsModule, RouterLink],
  styleUrls:  ['../../../../../styles/admin-page.css', './approval-policy-list.component.css'],
  templateUrl: './approval-policy-list.component.html',
})
export class ApprovalPolicyListComponent implements OnInit {
  private readonly svc = inject(ApprovalsAdminService);

  readonly items    = signal<ApprovalPolicy[]>([]);
  readonly loading  = signal(true);
  readonly error    = signal<string | null>(null);
  readonly busyId   = signal<string | null>(null);

  readonly editing  = signal<ApprovalPolicy | null>(null);
  readonly formOpen = signal(false);

  name       = '';
  actionType = '';
  condition  = '';
  isActive   = true;
  steps      = signal<StepDraft[]>([emptyStep()]);

  ngOnInit(): void { this.load(); }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listPolicies().subscribe({
      next:  res => { this.items.set(res.items); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(e.message); this.loading.set(false); },
    });
  }

  openCreate(): void {
    this.editing.set(null);
    this.name = '';
    this.actionType = '';
    this.condition = '';
    this.isActive = true;
    this.steps.set([emptyStep()]);
    this.formOpen.set(true);
  }

  openEdit(p: ApprovalPolicy): void {
    this.editing.set(p);
    this.name = p.name;
    this.actionType = p.action_type;
    this.condition = p.condition ?? '';
    this.isActive = p.is_active;
    this.steps.set(
      p.plan.steps.map((s: ApprovalStep): StepDraft => ({
        mode: s.mode,
        threshold: s.threshold != null ? String(s.threshold) : '',
        approvers: s.approvers.join(', '),
        sla_minutes: s.sla_minutes != null ? String(s.sla_minutes) : '',
        on_timeout: s.on_timeout,
      })),
    );
    this.formOpen.set(true);
  }

  closeForm(): void {
    this.formOpen.set(false);
    this.error.set(null);
  }

  addStep(): void {
    this.steps.update(s => [...s, emptyStep()]);
  }

  removeStep(index: number): void {
    this.steps.update(s => s.filter((_, i) => i !== index));
  }

  private buildPlan(): { steps: ApprovalStep[] } | null {
    const steps: ApprovalStep[] = [];
    for (const draft of this.steps()) {
      const approvers = draft.approvers
        .split(',')
        .map(t => t.trim())
        .filter(t => t.length > 0);
      if (approvers.length === 0) {
        this.error.set('every step needs at least one approver token');
        return null;
      }
      steps.push({
        mode: draft.mode,
        threshold: draft.mode === 'n_of_m' && draft.threshold.trim() !== ''
          ? Number(draft.threshold) : null,
        approvers,
        sla_minutes: draft.sla_minutes.trim() !== '' ? Number(draft.sla_minutes) : null,
        on_timeout: draft.on_timeout,
      });
    }
    if (steps.length === 0) {
      this.error.set('a plan needs at least one step');
      return null;
    }
    return { steps };
  }

  save(): void {
    const plan = this.buildPlan();
    if (!plan) return;
    if (!this.name.trim()) { this.error.set('name is required'); return; }

    const editing = this.editing();
    if (editing) {
      this.busyId.set(editing.id);
      this.svc.updatePolicy(editing.id, {
        name: this.name.trim(),
        is_active: this.isActive,
        condition: this.condition.trim() || null,
        plan,
        row_version: editing.row_version,
      }).subscribe({
        next: () => { this.busyId.set(null); this.formOpen.set(false); this.load(); },
        error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
      });
    } else {
      if (!this.actionType.trim()) { this.error.set('action_type is required'); return; }
      this.busyId.set('new');
      this.svc.createPolicy({
        name: this.name.trim(),
        is_active: this.isActive,
        action_type: this.actionType.trim(),
        condition: this.condition.trim() || null,
        plan,
      }).subscribe({
        next: () => { this.busyId.set(null); this.formOpen.set(false); this.load(); },
        error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
      });
    }
  }

  remove(p: ApprovalPolicy): void {
    this.busyId.set(p.id);
    this.svc.deletePolicy(p.id).subscribe({
      next:  () => { this.busyId.set(null); this.load(); },
      error: (e: ApiError) => { this.busyId.set(null); this.error.set(e.message); },
    });
  }

  stepCount(p: ApprovalPolicy): number {
    return p.plan.steps.length;
  }
}
