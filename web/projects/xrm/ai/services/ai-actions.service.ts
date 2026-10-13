import { inject, Injectable } from '@angular/core';
import { map, Observable } from 'rxjs';
import { ApiService } from '@attome/base';

/** One action the current caller may invoke, as `GET /api/v1/actions` reports it. */
export interface ActionSummary {
  id:          string;
  description: string;
  /** `Read` | `Reversible` | `Consequential`. */
  risk:        string;
  cacheable:   boolean;
}

/**
 * Where a generated suggestion came from. Rides on every model-backed result
 * so the UI can report the outcome against the right row — and so an auditor
 * can later answer "which model wrote this".
 */
export interface Provenance {
  model_id:       string;
  prompt_version: string;
  suggestion_id:  string | null;
}

/**
 * What an invocation produced. A discriminated union, matching the backend's
 * `#[serde(tag = "status")]` — the two non-`completed` arms are NOT errors and
 * must not be rendered as failures: they mean the gate stopped short of
 * running the action, and nothing has happened.
 */
export type ActionOutcome =
  | { status: 'completed'; result: unknown; provenance?: Provenance }
  | { status: 'confirmation_required'; reason: string }
  | { status: 'approval_required' };

/** What a human did with a suggestion. There is deliberately no 'pending'. */
export type SuggestionDecision =
  | { outcome: 'accepted' }
  | { outcome: 'rejected' }
  | { outcome: 'edited'; edit_distance: number };

@Injectable({ providedIn: 'root' })
export class AiActionsService {
  private readonly api = inject(ApiService);

  /**
   * The actions this caller may invoke.
   *
   * An empty list is the normal, expected response on a deployment that has
   * not licensed AI or has the kill-switch off — it is not an error state, and
   * a component that renders "something went wrong" for it is wrong. The
   * backend deliberately makes unlicensed and switched-off indistinguishable,
   * so there is nothing here to tell the user beyond "this is not available".
   */
  listActions(): Observable<ActionSummary[]> {
    return this.api
      .get<{ items: ActionSummary[] }>('/api/v1/actions')
      .pipe(map((r) => r.items ?? []));
  }

  invoke(actionId: string, args: unknown): Observable<ActionOutcome> {
    return this.api.post<ActionOutcome>(
      `/api/v1/actions/${encodeURIComponent(actionId)}/invoke`,
      { args },
    );
  }

  summarizeRecord(
    entity: string,
    recordId: string,
    language?: string,
  ): Observable<ActionOutcome> {
    return this.invoke('record.summarize', {
      entity,
      record_id: recordId,
      ...(language ? { language } : {}),
    });
  }

  /**
   * Reports what the human did with a suggestion (TODO-054).
   *
   * **Call this on every terminal interaction, including rejection.** The
   * outcome log is the only per-customer ground truth for generation quality
   * that will ever exist and it cannot be backfilled — a UI that reports
   * accepts but silently drops rejects produces a log that is not merely
   * incomplete but systematically biased upward.
   */
  recordOutcome(
    suggestionId: string,
    decision: SuggestionDecision,
  ): Observable<{ recorded: boolean }> {
    return this.api.post<{ recorded: boolean }>(
      `/api/v1/ai/suggestions/${encodeURIComponent(suggestionId)}/outcome`,
      decision,
    );
  }
}

/**
 * Levenshtein distance, used to report how much a human changed a suggestion.
 *
 * A distance, not the before/after texts — the backend deliberately stores no
 * generated or edited text, so this is computed client-side and only the
 * number is sent. "The human changed four characters" is the signal; the texts
 * would make the outcome log a second copy of customer business data with its
 * own erasure obligation.
 *
 * Bounded to keep a long suggestion from costing an O(n·m) walk on the UI
 * thread: past the cap the exact number stops carrying information anyway
 * ("they rewrote it").
 */
export function editDistance(a: string, b: string, cap = 2000): number {
  if (a === b) return 0;
  if (a.length > cap || b.length > cap) return cap;

  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    for (let j = 1; j <= b.length; j++) {
      const substitution = previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1);
      current[j] = Math.min(previous[j] + 1, current[j - 1] + 1, substitution);
    }
    previous = current;
  }
  return previous[b.length];
}
