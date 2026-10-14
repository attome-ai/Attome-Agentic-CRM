import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, TranslatePipe } from '@attome/base';

import { ActionSummary, ModelCommand, ModelIssue, ModelService, ObjectSummary } from '../model.service';

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
}

export const AGENT_CHANNELS = ['chat', 'web', 'whatsapp', 'sms', 'email'] as const;

export function emptyAgent(): AgentDraft {
  return {
    role: '', instructions: '', tools: [], runAs: 'caller',
    maxSteps: 20, maxToolCalls: 40, maxTokens: 60000, channels: ['chat'],
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
  };
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
    } },
    { op: 'set', path: '/channels', value: [...draft.channels] },
  ];
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

  readonly editing = computed(() => this.selected() !== null);
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
      },
      error: (e: ApiError) => this.error.set(e.message),
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
      next: () => { this.saving.set(false); this.status.set('published'); this.loadAgents(); },
      error: (e: ApiError) => { this.error.set(e.message); this.saving.set(false); },
    });
  }

  numberFrom(value: string): number {
    const n = Number.parseInt(value, 10);
    return Number.isFinite(n) ? n : 0;
  }
}
