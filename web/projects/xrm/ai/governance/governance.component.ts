import { ChangeDetectionStrategy, Component, OnInit, inject, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe, type Page } from '@attome/base';

/** `write_policy::WritePolicy`. */
export interface WritePolicy {
  id:         string;
  action_id:  string;
  entity:     string | null;
  reason:     string | null;
  created_at: string;
}

/** `approval_metrics::ApprovalMetrics`. */
export interface ApprovalMetrics {
  days: number;
  approvers: { approver_id: string; decisions: number; approved: number; median_seconds: number | null; warning: boolean }[];
  backlog: { action_type: string; pending: number; oldest: string | null }[];
  rejection_words: { word: string; count: number }[];
}

/** Share approved, as a whole percentage. */
export function approvedShare(a: { decisions: number; approved: number }): number {
  return a.decisions > 0 ? Math.round((100 * a.approved) / a.decisions) : 0;
}

/**
 * AI governance (roadmap N30-T5, T9): the per-write approval policies — off
 * until one names an action — and how approvals are going: per approver,
 * with rubber-stamp warnings, the backlog and common rejection words.
 * Logical CSS only.
 */
@Component({
  selector:        'xrm-ai-governance',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [LocalDatePipe, TranslatePipe],
  templateUrl:     './governance.component.html',
  styleUrls:       ['./governance.component.css'],
})
export class AiGovernanceComponent implements OnInit {
  private readonly api = inject(ApiService);

  readonly policies = signal<WritePolicy[]>([]);
  readonly writeActions = signal<string[]>([]);
  readonly metrics  = signal<ApprovalMetrics | null>(null);
  readonly error    = signal<string | null>(null);
  readonly newAction = signal('');
  readonly newEntity = signal('');
  readonly approvedShare = approvedShare;

  ngOnInit(): void {
    this.loadPolicies();
    this.api.get<{ items: { id: string; risk: string }[] }>('/api/v1/actions').subscribe({
      next: r => this.writeActions.set((r.items ?? []).filter(a => a.risk !== 'Read').map(a => a.id)),
      error: () => this.writeActions.set([]),
    });
    this.api.get<ApprovalMetrics>('/api/v1/admin/approvals/metrics').subscribe({
      next: m => this.metrics.set(m),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  loadPolicies(): void {
    this.api.get<Page<WritePolicy>>('/api/v1/admin/ai/write-policies').subscribe({
      next: page => this.policies.set(page.items ?? []),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  addPolicy(): void {
    const action = this.newAction().trim();
    if (!action) return;
    const entity = this.newEntity().trim();
    this.api.post<WritePolicy>('/api/v1/admin/ai/write-policies', {
      action_id: action, ...(entity ? { entity } : {}),
    }).subscribe({
      next: () => { this.newAction.set(''); this.newEntity.set(''); this.loadPolicies(); },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  removePolicy(policy: WritePolicy): void {
    this.api.delete(`/api/v1/admin/ai/write-policies/${encodeURIComponent(policy.id)}`).subscribe({
      next: () => this.loadPolicies(),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
