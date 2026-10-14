import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { forkJoin, switchMap, takeWhile, timer } from 'rxjs';
import { ApiError, TranslatePipe } from '@attome/base';

import { ActionSummary, AgentUsage, EvalRun, ModelCommand, ModelIssue, ModelService, ObjectSummary } from '../model.service';

/** The editable parts of an agent document (`attome_model::kinds::agent`). */
export interface AgentDraft {
  role:         string;
  instructions: string;
  tools:        string[];
  runAs:        'caller' | 'service';
  maxSteps:     number;
  maxToolCalls: number;
  maxTokens:    number;
  channels:     string[];
  /** Per-day caps by limit class; a missing class has no cap (V2-D487). */
  daily:        Partial<Record<DailyClass, number>>;
  /**
   * The typed contract supervisors delegate through (N8-T1), as JSON text
   * so it can be edited; `null` when the agent takes no delegated work.
   */
  handoff:      { input: string; output: string } | null;
  /** Whether the stored document had a handoff, so clearing it removes it. */
  hadHandoff:   boolean;
  /** The `ai_agent_policy` id sessions from this agent run under (V2-D487). */
  policy:       string;
  /** `persona.model`: the AI model id. */
  model:        string;
  /** `persona.language`: `ar`, `en`, ... or empty. */
  language:     string;
  /** Other persona settings (temperature, ...), kept as they are. */
  personaRest:  Record<string, unknown>;
}

/** An empty object contract, the starting point when a handoff is added. */
export const EMPTY_CONTRACT = '{\n  "type": "object",\n  "properties": {}\n}';

export const DAILY_CLASSES = ['record_changes', 'deletes', 'messages', 'external_calls'] as const;
export type DailyClass = typeof DAILY_CLASSES[number];

export const AGENT_CHANNELS = ['chat', 'web', 'whatsapp', 'sms', 'email'] as const;

export function emptyAgent(): AgentDraft {
  return {
    role: '', instructions: '', tools: [], runAs: 'caller',
    maxSteps: 20, maxToolCalls: 40, maxTokens: 60000, channels: ['chat'], daily: {},
    handoff: null, hadHandoff: false,
    policy: '', model: '', language: '', personaRest: {},
  };
}

/** Reads an agent document into the form, tolerating missing parts. */
export function draftFromDoc(doc: unknown): AgentDraft {
  const d = (doc ?? {}) as Record<string, unknown>;
  const limits = (d['limits'] ?? {}) as Record<string, unknown>;
  const identity = (d['identity'] ?? {}) as Record<string, unknown>;
  const base = emptyAgent();
  const list = (value: unknown) => Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
  return {
    role:         typeof d['role'] === 'string' ? d['role'] : '',
    instructions: typeof d['instructions'] === 'string' ? d['instructions'] : '',
    tools:        list(d['tools']),
    runAs:        identity['run_as'] === 'service' ? 'service' : 'caller',
    maxSteps:     typeof limits['max_steps'] === 'number' ? limits['max_steps'] : base.maxSteps,
    maxToolCalls: typeof limits['max_tool_calls'] === 'number' ? limits['max_tool_calls'] : base.maxToolCalls,
    maxTokens:    typeof limits['max_tokens'] === 'number' ? limits['max_tokens'] : base.maxTokens,
    channels:     d['channels'] === undefined ? base.channels : list(d['channels']),
    daily:        dailyFrom(limits['daily']),
    ...handoffFrom(d['handoff']),
    ...personaFrom(d['persona']),
    policy: typeof d['policy'] === 'string' ? d['policy'] : '',
  };
}

function personaFrom(value: unknown): Pick<AgentDraft, 'model' | 'language' | 'personaRest'> {
  const p = (value && typeof value === 'object' ? value : {}) as Record<string, unknown>;
  const personaRest: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(p)) {
    if (key !== 'model' && key !== 'language') personaRest[key] = v;
  }
  return {
    model:    typeof p['model'] === 'string' ? p['model'] : '',
    language: typeof p['language'] === 'string' ? p['language'] : '',
    personaRest,
  };
}

function handoffFrom(value: unknown): Pick<AgentDraft, 'handoff' | 'hadHandoff'> {
  const h = value as Record<string, unknown> | null | undefined;
  if (!h || typeof h !== 'object') return { handoff: null, hadHandoff: false };
  return {
    handoff: {
      input:  JSON.stringify(h['input'] ?? {}, null, 2),
      output: JSON.stringify(h['output'] ?? {}, null, 2),
    },
    hadHandoff: true,
  };
}

/** What is wrong with the handoff text, or `null` when it is usable JSON. */
export function handoffError(draft: AgentDraft): 'input' | 'output' | null {
  if (!draft.handoff) return null;
  for (const side of ['input', 'output'] as const) {
    try {
      const value: unknown = JSON.parse(draft.handoff[side]);
      if (!value || typeof value !== 'object' || Array.isArray(value)) return side;
    } catch {
      return side;
    }
  }
  return null;
}

function dailyFrom(value: unknown): Partial<Record<DailyClass, number>> {
  const out: Partial<Record<DailyClass, number>> = {};
  const raw = (value ?? {}) as Record<string, unknown>;
  for (const key of DAILY_CLASSES) {
    if (typeof raw[key] === 'number') out[key] = raw[key];
  }
  return out;
}

/**
 * The commands that make a draft's document equal to `draft`: one `set` per
 * top-level property, so the server's own validation sees the whole agent.
 */
export function commandsFor(draft: AgentDraft): ModelCommand[] {
  return [
    { op: 'set', path: '/role', value: draft.role.trim() },
    { op: 'set', path: '/instructions', value: draft.instructions },
    { op: 'set', path: '/tools', value: [...draft.tools] },
    { op: 'set', path: '/identity', value: { run_as: draft.runAs } },
    { op: 'set', path: '/limits', value: {
      max_steps: draft.maxSteps, max_tool_calls: draft.maxToolCalls, max_tokens: draft.maxTokens,
      ...(Object.keys(draft.daily).length > 0 ? { daily: { ...draft.daily } } : {}),
    } },
    { op: 'set', path: '/channels', value: [...draft.channels] },
    ...handoffCommands(draft),
    ...runtimeCommands(draft),
  ];
}

/** The policy and persona, set only when there is something to set. */
function runtimeCommands(draft: AgentDraft): ModelCommand[] {
  const out: ModelCommand[] = [];
  if (draft.policy.trim()) out.push({ op: 'set', path: '/policy', value: draft.policy.trim() });
  const persona: Record<string, unknown> = { ...draft.personaRest };
  if (draft.model.trim()) persona['model'] = draft.model.trim();
  if (draft.language.trim()) persona['language'] = draft.language.trim();
  if (Object.keys(persona).length > 0) out.push({ op: 'set', path: '/persona', value: persona });
  return out;
}

/** Sets the handoff when there is one, removes it when it was cleared. */
function handoffCommands(draft: AgentDraft): ModelCommand[] {
  if (draft.handoff && handoffError(draft) === null) {
    return [{ op: 'set', path: '/handoff', value: {
      input: JSON.parse(draft.handoff.input) as unknown,
      output: JSON.parse(draft.handoff.output) as unknown,
    } }];
  }
  if (!draft.handoff && draft.hadHandoff) return [{ op: 'remove', path: '/handoff' }];
  return [];
}

/** A UUIDv7 (time-ordered, as the platform's own ids are) for a new agent. */
export function newId(now = Date.now()): string {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  let ts = now;
  for (let i = 5; i >= 0; i--) {
    bytes[i] = ts % 256;
    ts = Math.floor(ts / 256);
  }
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * The agent designer (roadmap N9-T2, first step): list agents, define one
 * (role, instructions, tools, identity, limits, channels), save it as a
 * draft and publish it. Every check is the server's (the agent kind, N9-T1);
 * its issues are shown by path. Test runs and trial mode arrive with the
 * agent runtime.
 */
@Component({
  selector:        'xrm-agent-designer',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './agent-designer.component.html',
  styleUrls:       ['./agent-designer.component.css'],
})
export class AgentDesignerComponent implements OnInit {
  private readonly model = inject(ModelService);
  private readonly destroyRef = inject(DestroyRef);

  /** The eval suites that test the open agent (N9-T2), once asked for. */
  readonly suites = signal<{ id: string; name: string }[] | null>(null);
  /** The latest run of each suite, by suite id. */
  readonly runs = signal<Record<string, EvalRun>>({});

  readonly channels  = AGENT_CHANNELS;
  readonly agents    = signal<ObjectSummary[]>([]);
  readonly actions   = signal<ActionSummary[]>([]);
  readonly selected  = signal<string | null>(null);
  /** Set only while creating an agent: its name. */
  readonly newName   = signal<string | null>(null);
  readonly draft     = signal<AgentDraft>(emptyAgent());
  readonly baseHash  = signal('');
  readonly issues    = signal<ModelIssue[]>([]);
  readonly saving    = signal(false);
  readonly status    = signal<'saved' | 'published' | null>(null);
  readonly error     = signal<string | null>(null);
  /** Today's use against the daily limits; empty until the agent is published. */
  readonly usage     = signal<AgentUsage[]>([]);

  readonly editing = computed(() => this.selected() !== null);
  readonly handoffInvalid = computed(() => handoffError(this.draft()));
  readonly canPublish = computed(() => this.baseHash() !== '' && !this.saving());

  ngOnInit(): void {
    this.loadAgents();
    this.model.actions().subscribe({
      next: list => this.actions.set(list.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  loadAgents(): void {
    this.model.objects('agent', 1).subscribe({
      next: page => this.agents.set(page.items),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  create(): void {
    this.selected.set(newId());
    this.newName.set('');
    this.draft.set(emptyAgent());
    this.baseHash.set('');
    this.issues.set([]);
    this.status.set(null);
  }

  open(agent: ObjectSummary): void {
    this.model.object('agent', agent.id).subscribe({
      next: version => {
        this.selected.set(agent.id);
        this.newName.set(null);
        this.draft.set(draftFromDoc(version.doc));
        this.baseHash.set(version.content_hash);
        this.issues.set([]);
        this.status.set(null);
        this.loadUsage(agent.id);
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Usage exists only for a published agent; a draft-only one shows none. */
  loadUsage(id: string): void {
    this.usage.set([]);
    this.model.agentUsage(id).subscribe({
      next: result => this.usage.set(result.items),
      error: () => this.usage.set([]),
    });
  }

  update(patch: Partial<AgentDraft>): void {
    this.draft.update(current => ({ ...current, ...patch }));
    this.status.set(null);
  }

  toggle(list: 'tools' | 'channels', value: string, on: boolean): void {
    const current = this.draft()[list];
    const next = on ? [...current.filter(v => v !== value), value] : current.filter(v => v !== value);
    this.update({ [list]: next } as Partial<AgentDraft>);
  }

  save(): void {
    const id = this.selected();
    if (!id) return;
    this.saving.set(true);
    this.error.set(null);
    this.model.saveDraft('agent', id, this.baseHash(), this.newName(), commandsFor(this.draft())).subscribe({
      next: saved => {
        this.baseHash.set(saved.content_hash);
        this.issues.set(saved.issues);
        this.newName.set(null);
        this.saving.set(false);
        this.status.set('saved');
        this.loadAgents();
      },
      error: (e: ApiError) => { this.error.set(e.message); this.saving.set(false); },
    });
  }

  publish(): void {
    const id = this.selected();
    if (!id) return;
    this.saving.set(true);
    this.error.set(null);
    this.model.publish('agent', id).subscribe({
      next: () => { this.saving.set(false); this.status.set('published'); this.loadAgents(); this.loadUsage(id); },
      error: (e: ApiError) => { this.error.set(e.message); this.saving.set(false); },
    });
  }

  readonly dailyClasses = DAILY_CLASSES;

  /** Sets one daily cap; a blank input removes it. */
  setDaily(key: DailyClass, value: string): void {
    const n = Number.parseInt(value, 10);
    const cleared = value.trim() === '' || !Number.isFinite(n);
    const daily: Partial<Record<DailyClass, number>> = {};
    for (const [k, v] of Object.entries(this.draft().daily) as [DailyClass, number][]) {
      if (k !== key) daily[k] = v;
    }
    if (!cleared) daily[key] = Math.max(0, n);
    this.update({ daily });
  }

  /** Adds an empty contract pair, or removes the handoff. */
  setHandoff(on: boolean): void {
    this.update({ handoff: on ? { input: EMPTY_CONTRACT, output: EMPTY_CONTRACT } : null });
  }

  setHandoffSide(side: 'input' | 'output', text: string): void {
    const current = this.draft().handoff ?? { input: EMPTY_CONTRACT, output: EMPTY_CONTRACT };
    this.update({ handoff: { ...current, [side]: text } });
  }

  /** Lists the eval suites whose `agent` is the open agent. */
  loadSuites(): void {
    const agent = this.selected();
    if (!agent) return;
    this.model.objects('eval_suite', 1).subscribe({
      next: page => {
        const items = page.items ?? [];
        if (items.length === 0) { this.suites.set([]); return; }
        forkJoin(items.map(s => this.model.object('eval_suite', s.id))).subscribe({
          next: versions => this.suites.set(versions
            .filter(v => (v.doc as Record<string, unknown> | null)?.['agent'] === agent)
            .map(v => ({ id: v.id, name: v.name }))),
          error: (e: ApiError) => this.error.set(e.message),
        });
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  /** Runs a suite and follows the run until it finishes. */
  runSuite(suite: string): void {
    this.model.startEvalRun(suite).pipe(
      switchMap(started => timer(0, 3000).pipe(switchMap(() => this.model.evalRun(started.run_id)))),
      takeWhile(run => run.status === 'running', true),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe({
      next: run => this.runs.set({ ...this.runs(), [suite]: run }),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  numberFrom(value: string): number {
    const n = Number.parseInt(value, 10);
    return Number.isFinite(n) ? n : 0;
  }
}
