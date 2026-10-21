import { Injectable, inject } from '@angular/core';
import { ApiService, type Page } from '@attome/base';
import { Observable } from 'rxjs';

/** `attome_ai::agent_stats_routes::AgentPerformance`. */
export interface AgentPerformance {
  agent_id: string;
  name: string | null;
  tasks_done: number;
  tasks_resolved: number;
  tasks_measured: number;
  effectiveness_sum: number;
  handoffs: number;
  input_tokens: number;
  output_tokens: number;
  cost_micros: number;
  cost_unit: string | null;
  time_saved_seconds: number;
  resolution_rate: number | null;
  accuracy: number | null;
  handoff_rate: number | null;
  cost_per_task_micros: number | null;
}

/** `attome_ai::agent_stats_routes::AgentPerformanceDay`. */
export interface AgentPerformanceDay {
  day: string;
  tasks_done: number;
  tasks_resolved: number;
  tasks_measured: number;
  effectiveness_sum: number;
  handoffs: number;
  input_tokens: number;
  output_tokens: number;
  cost_micros: number;
  cost_unit: string | null;
  time_saved_seconds: number;
}

/** `attome_ai::agent_stats_routes::AgentRun`. */
export interface AgentRun {
  kind: 'outcome' | 'session' | string;
  id: string;
  at: string;
  session_id: string | null;
  source: string | null;
  regarding_entity: string | null;
  regarding_id: string | null;
  measured_at: string | null;
  input_tokens: number | null;
  output_tokens: number | null;
}

/** `attome_types::CursorPage<AgentRun>`. */
export interface RunsPage {
  items: AgentRun[];
  next_cursor: string | null;
  total?: number | null;
}

export type RunsMetric = 'tasks' | 'handoffs' | 'cost';

/** AH5-T5: `attome_ai::behaviour_routes::AgentBehaviour`. */
export interface AgentBehaviour {
  agent_id: string;
  name: string | null;
  status: string | null;
  row_version: number;
  baseline: {
    computed_at: string;
    first_activity_at: string | null;
    mean_writes_per_hour: number | null;
    stddev_writes_per_hour: number | null;
    mean_deletes_per_hour: number | null;
    stddev_deletes_per_hour: number | null;
    usual_entities: string[];
    usual_hours: number[];
  } | null;
  hours: { hour: string; writes: number; deletes: number; external_calls: number; entities: string[] }[];
  last_trip: { at: string; reason: string | null } | null;
}

/** AI8-T6: the agent performance routes (AI8-T4). */
@Injectable({ providedIn: 'root' })
export class AiAgentPerformanceService {
  private readonly api = inject(ApiService);

  summary(from: string, to: string): Observable<Page<AgentPerformance>> {
    return this.api.get<Page<AgentPerformance>>(
      `/api/v1/admin/ai/agents/performance?from=${from}&to=${to}`,
    );
  }

  daily(agentId: string, from: string, to: string): Observable<Page<AgentPerformanceDay>> {
    return this.api.get<Page<AgentPerformanceDay>>(
      `/api/v1/admin/ai/agents/${encodeURIComponent(agentId)}/performance/daily?from=${from}&to=${to}`,
    );
  }

  /** AH5-T5: the agent's status, baseline, last 24 hours and last automatic stop. */
  behaviour(agentId: string): Observable<AgentBehaviour> {
    return this.api.get<AgentBehaviour>(`/api/v1/admin/ai/agents/${encodeURIComponent(agentId)}/behaviour`);
  }

  /** AH5-T5: a person switches a stopped agent back on: the ordinary update, with If-Match. */
  switchOn(agentId: string, rowVersion: number): Observable<unknown> {
    return this.api.patch<unknown>(`/api/v1/ai_agent/${encodeURIComponent(agentId)}`, { status: 'active' }, rowVersion);
  }

  runs(agentId: string, day: string, metric: RunsMetric, cursor?: string | null): Observable<RunsPage> {
    const after = cursor ? `&cursor=${encodeURIComponent(cursor)}` : '';
    return this.api.get<RunsPage>(
      `/api/v1/admin/ai/agents/${encodeURIComponent(agentId)}/runs?day=${day}&metric=${metric}${after}`,
    );
  }
}
