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

/** Saves `data` as a JSON file in the browser. */
export function saveJson(name: string, data: unknown): void {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
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
  /** Evidence export (N29-T2): what to export and how far it got. */
  readonly evidenceKind = signal<'actions' | 'generations'>('actions');
  readonly evidenceFrom = signal('');
  readonly evidenceTo   = signal('');
  readonly exporting    = signal(false);
  readonly exportedRows = signal<number | null>(null);

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

  /** Fetches every page of evidence for the period and saves it as one JSON file. */
  exportEvidence(): void {
    const rows: unknown[] = [];
    const base: Record<string, string> = { kind: this.evidenceKind() };
    if (this.evidenceFrom()) base['from'] = new Date(this.evidenceFrom()).toISOString();
    if (this.evidenceTo()) base['to'] = new Date(this.evidenceTo()).toISOString();
    this.exporting.set(true);
    this.exportedRows.set(null);
    const page = (cursor: string | null): void => {
      const params = cursor ? { ...base, cursor } : base;
      this.api.get<{ items: unknown[]; next_cursor: string | null }>('/api/v1/admin/ai/evidence', params).subscribe({
        next: r => {
          rows.push(...(r.items ?? []));
          if (r.next_cursor) { page(r.next_cursor); return; }
          this.exporting.set(false);
          this.exportedRows.set(rows.length);
          saveJson(`attome-ai-evidence-${this.evidenceKind()}.json`, rows);
        },
        error: (e: ApiError) => { this.exporting.set(false); this.error.set(e.message); },
      });
    };
    page(null);
  }

  removePolicy(policy: WritePolicy): void {
    this.api.delete(`/api/v1/admin/ai/write-policies/${encodeURIComponent(policy.id)}`).subscribe({
      next: () => this.loadPolicies(),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
