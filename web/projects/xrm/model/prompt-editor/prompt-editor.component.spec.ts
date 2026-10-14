import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ModelService } from '../model.service';
import { PromptEditorComponent, emptyOverride, overrideCommands, overrideFromDoc } from './prompt-editor.component';

describe('prompt overrides (N10-T4)', () => {
  it('reads an override and writes it back with its rollout', () => {
    const draft = overrideFromDoc('o1', 'h1', {
      prompt: 'record.summarize',
      sections: [{ name: 'tone', text: 'Be brief.' }],
      rollout: { share: 20 },
    });
    expect(draft).toEqual({ id: 'o1', baseHash: 'h1', sections: [{ name: 'tone', text: 'Be brief.' }], share: 20 });
    expect(overrideCommands('record.summarize', draft)).toEqual([
      { op: 'set', path: '/prompt', value: 'record.summarize' },
      { op: 'set', path: '/sections', value: [{ name: 'tone', text: 'Be brief.' }] },
      { op: 'set', path: '/rollout', value: { share: 20 } },
    ]);
  });

  it('drops empty sections and writes no rollout for a new override at 100%', () => {
    const draft = { ...emptyOverride(), sections: [{ name: 'tone', text: 'Warm.' }, { name: '', text: '' }] };
    expect(overrideCommands('text.translate', draft)).toEqual([
      { op: 'set', path: '/prompt', value: 'text.translate' },
      { op: 'set', path: '/sections', value: [{ name: 'tone', text: 'Warm.' }] },
    ]);
  });

  it('lists the shipped prompts and marks the customised ones', () => {
    const api = {
      get: vi.fn().mockReturnValue(of({ items: [
        { action_id: 'record.summarize', version: 'record.summarize/v2', text: 'LOCKED' },
        { action_id: 'text.translate', version: 'text.translate/v1', text: 'LOCKED 2' },
      ] })),
      post: vi.fn(),
    };
    const model = {
      objects: vi.fn().mockReturnValue(of({ items: [{ id: 'o1' }], total: 1, page: 1, page_size: 50 })),
      object: vi.fn().mockReturnValue(of({ id: 'o1', content_hash: 'h1', doc: { prompt: 'record.summarize', sections: [] } })),
      saveDraft: vi.fn(), publish: vi.fn(),
    };
    TestBed.configureTestingModule({
      imports: [PromptEditorComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: ModelService, useValue: model },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
    const fixture = TestBed.createComponent(PromptEditorComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-prompt="record.summarize"]')?.textContent).toContain('promptEditor.customised');
    expect(el.querySelector('[data-prompt="text.translate"]')?.textContent).not.toContain('promptEditor.customised');
    fixture.componentInstance.select(fixture.componentInstance.prompts()[0]);
    fixture.detectChanges();
    expect(fixture.componentInstance.canPreview()).toBe(true);
    expect(el.textContent).toContain('LOCKED');
  });
});
