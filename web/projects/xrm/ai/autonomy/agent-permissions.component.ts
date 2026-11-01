import { ChangeDetectionStrategy, Component, effect, inject, input, signal } from '@angular/core';
import { ApiError, ApiService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** `permission_test::Failure`. */
export interface PermissionFailure {
  action_id: string;
  entity:    string | null;
  expect:    'allowed' | 'refused' | 'needs_approval';
  got:       'allowed' | 'refused' | 'needs_approval';
  reason:    string;
}

/** `permission_test::CaseSummary`. */
export interface PermissionSummary {
  cannot_do:           string[];
  unreadable_entities: string[];
  needs_approval:      string[];
}

/** `permission_test::Report`. */
export interface PermissionReport {
  run_id:             string;
  agent_ref:          string;
  passed:             boolean;
  cases:              number;
  failures:           PermissionFailure[];
  failures_truncated: boolean;
  over_restricted:    number;
  summary:            PermissionSummary;
}

/** `permission_test::PermissionTestRun`. */
export interface PermissionTestRun {
  id:         string;
  passed:     boolean;
  cases:      number;
  created_at: string;
}

interface RunPage {
  items: PermissionTestRun[];
}

/**
 * An agent's permission test (roadmap AH7-T5): run it, see any failure
 * first, then what the agent cannot do and what waits for a person, and
 * when it last ran. Logical CSS only.
 */
@Component({
  selector:        'xrm-ai-agent-permissions',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [LocalDatePipe, TranslatePipe],
  templateUrl:     './agent-permissions.component.html',
  styleUrls:       ['./autonomy.component.css'],
})
export class AiAgentPermissionsComponent {
  private readonly api = inject(ApiService);

  readonly agentId = input.required<string>();
  readonly report  = signal<PermissionReport | null>(null);
  readonly lastRun = signal<PermissionTestRun | null>(null);
  readonly error   = signal<string | null>(null);
  readonly busy    = signal(false);

  constructor() {
    effect(() => this.loadLast(this.agentId()));
  }

  private base(): string {
    return `/api/v1/admin/ai/agents/${encodeURIComponent(this.agentId())}`;
  }

  loadLast(agentId: string): void {
    this.api
      .get<RunPage>(`/api/v1/admin/ai/agents/${encodeURIComponent(agentId)}/permission-tests?page=1&page_size=1`)
      .subscribe({
        next: page => this.lastRun.set(page.items[0] ?? null),
        error: (e: ApiError) => this.error.set(e.message),
      });
  }

  run(): void {
    this.busy.set(true);
    this.error.set(null);
    this.api.post<PermissionReport>(`${this.base()}/permission-test`, {}).subscribe({
      next: r => {
        this.busy.set(false);
        this.report.set(r);
        this.lastRun.set({ id: r.run_id, passed: r.passed, cases: r.cases, created_at: new Date().toISOString() });
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }
}
