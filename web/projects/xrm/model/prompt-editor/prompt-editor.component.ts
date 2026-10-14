import { ChangeDetectionStrategy, Component, OnInit, computed, inject, signal } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';
import { forkJoin } from 'rxjs';

import { newId } from '../agent-designer/agent-designer.component';
import { ModelCommand, ModelService } from '../model.service';

/** One shipped prompt (`GET /api/v1/admin/ai/prompts`). */
export interface ShippedPrompt {
  action_id: string;
  version:   string;
  text:      string;
}

/** One editable section of an override. */
export interface OverrideSection {
  name: string;
  text: string;
}

/** An override as the editor holds it. */
export interface OverrideDraft {
  /** The override object, once it exists. */
  id:       string | null;
  baseHash: string;
  sections: OverrideSection[];
  /** 1 to 100; 100 means everyone (no rollout written). */
  share:    number;
}

export function emptyOverride(): OverrideDraft {
  return { id: null, baseHash: '', sections: [{ name: 'custom', text: '' }], share: 100 };
}

/** Reads an override document into the editor. */
export function overrideFromDoc(id: string, hash: string, doc: unknown): OverrideDraft {
  const d = (doc ?? {}) as Record<string, unknown>;
  const sections = Array.isArray(d['sections'])
    ? (d['sections'] as Record<string, unknown>[]).map(s => ({
        name: typeof s['name'] === 'string' ? s['name'] : '',
        text: typeof s['text'] === 'string' ? s['text'] : '',
      }))
    : [];
  const rollout = (d['rollout'] ?? {}) as Record<string, unknown>;
  return {
    id, baseHash: hash,
    sections: sections.length > 0 ? sections : emptyOverride().sections,
    share: typeof rollout['share'] === 'number' ? rollout['share'] : 100,
  };
}

/** The commands that make an override's document match the editor. */
export function overrideCommands(prompt: string, draft: OverrideDraft): ModelCommand[] {
  const sections = draft.sections
    .map(s => ({ name: s.name.trim(), text: s.text }))
    .filter(s => s.name !== '' && s.text.trim() !== '');
  const commands: ModelCommand[] = [
    { op: 'set', path: '/prompt', value: prompt },
    { op: 'set', path: '/sections', value: sections },
  ];
  const share = Math.max(1, Math.min(100, Math.round(draft.share)));
  if (share < 100) commands.push({ op: 'set', path: '/rollout', value: { share } });
  else if (draft.id) commands.push({ op: 'set', path: '/rollout', value: { share: 100 } });
  return commands;
}

/**
 * The prompt editor (roadmap N10-T4): every prompt the platform ships, the
 * administrator's override layered after its locked text (N10-T1) with a
 * staged rollout share (N10-T3), and, for the record summary, a try-on that
 * shows exactly what the model would receive (N28-T3). Saving writes a
 * `prompt_override` draft; publishing makes it live. Logical CSS only.
 */
@Component({
  selector:        'xrm-prompt-editor',
  standalone:      true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports:         [TranslatePipe],
  templateUrl:     './prompt-editor.component.html',
  styleUrls:       ['./prompt-editor.component.css'],
})
export class PromptEditorComponent implements OnInit {
  private readonly api = inject(ApiService);
  private readonly model = inject(ModelService);

  readonly prompts  = signal<ShippedPrompt[]>([]);
  /** Existing overrides by the prompt (action id) they change. */
  readonly overrides = signal<Record<string, { id: string; hash: string; doc: unknown }>>({});
  readonly selected = signal<ShippedPrompt | null>(null);
  readonly draft    = signal<OverrideDraft>(emptyOverride());
  readonly status   = signal<'saved' | 'published' | null>(null);
  readonly error    = signal<string | null>(null);
  readonly busy     = signal(false);
  readonly previewEntity = signal('');
  readonly previewRecord = signal('');
  readonly preview  = signal<{ role: string; content: string }[]>([]);

  readonly canPreview = computed(() => this.selected()?.action_id === 'record.summarize');

  ngOnInit(): void {
    this.api.get<{ items: ShippedPrompt[] }>('/api/v1/admin/ai/prompts').subscribe({
      next: r => this.prompts.set(r.items ?? []),
      error: (e: ApiError) => this.error.set(e.message),
    });
    this.loadOverrides();
  }

  loadOverrides(): void {
    this.model.objects('prompt_override', 1).subscribe({
      next: page => {
        const items = page.items ?? [];
        if (items.length === 0) { this.overrides.set({}); return; }
        forkJoin(items.map(o => this.model.object('prompt_override', o.id))).subscribe({
          next: versions => {
            const map: Record<string, { id: string; hash: string; doc: unknown }> = {};
            for (const v of versions) {
              const prompt = (v.doc as Record<string, unknown> | null)?.['prompt'];
              if (typeof prompt === 'string') map[prompt] = { id: v.id, hash: v.content_hash, doc: v.doc };
            }
            this.overrides.set(map);
          },
          error: (e: ApiError) => this.error.set(e.message),
        });
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  select(prompt: ShippedPrompt): void {
    this.selected.set(prompt);
    this.status.set(null);
    this.preview.set([]);
    const existing = this.overrides()[prompt.action_id];
    this.draft.set(existing ? overrideFromDoc(existing.id, existing.hash, existing.doc) : emptyOverride());
  }

  setSection(index: number, patch: Partial<OverrideSection>): void {
    this.draft.update(d => ({
      ...d,
      sections: d.sections.map((s, i) => (i === index ? { ...s, ...patch } : s)),
    }));
  }

  addSection(): void {
    this.draft.update(d => ({ ...d, sections: [...d.sections, { name: '', text: '' }] }));
  }

  setShare(value: string): void {
    const n = Number.parseInt(value, 10);
    this.draft.update(d => ({ ...d, share: Number.isFinite(n) ? n : 100 }));
  }

  save(): void {
    const prompt = this.selected();
    if (!prompt) return;
    const draft = this.draft();
    const id = draft.id ?? newId();
    this.busy.set(true);
    this.error.set(null);
    this.model.saveDraft(
      'prompt_override', id, draft.baseHash,
      draft.id ? null : `override ${prompt.action_id}`,
      overrideCommands(prompt.action_id, draft),
    ).subscribe({
      next: saved => {
        this.busy.set(false);
        this.draft.set({ ...draft, id, baseHash: saved.content_hash });
        this.status.set('saved');
      },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  publish(): void {
    const id = this.draft().id;
    if (!id) return;
    this.busy.set(true);
    this.model.publish('prompt_override', id).subscribe({
      next: () => { this.busy.set(false); this.status.set('published'); this.loadOverrides(); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(e.message); },
    });
  }

  /** Shows what the model would receive for one record (published override included). */
  tryOn(): void {
    const entity = this.previewEntity().trim();
    const record = this.previewRecord().trim();
    if (!entity || !record) return;
    this.preview.set([]);
    this.api.post<{ messages: { role: string; content: string }[] }>(
      '/api/v1/admin/ai/preview/summary', { entity, record_id: record },
    ).subscribe({
      next: r => this.preview.set(r.messages ?? []),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
