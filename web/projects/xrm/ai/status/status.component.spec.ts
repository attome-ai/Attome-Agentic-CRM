import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiStatus, AiStatusComponent, overall } from './status.component';

const base: AiStatus = {
  generation_model: 'qwen3', model_approved: true, model_cards: [], switched_off: 0,
  turns_last_day: [], timeline: [],
};

describe('AiStatusComponent (N31-T2)', () => {
  it('says down, degraded or up', () => {
    expect(overall(base)).toBe('up');
    expect(overall({ ...base, switched_off: 2 })).toBe('degraded');
    expect(overall({ ...base, model_approved: false })).toBe('down');
    expect(overall({ ...base, generation_model: '' })).toBe('down');
  });

  it('shows the model card, the day\'s turns and the timeline', () => {
    const api = { get: vi.fn().mockReturnValue(of({
      ...base,
      switched_off: 1,
      model_cards: [{ id: 'm1', name: 'Qwen3', version: '8B', provider_model_id: 'qwen3', approval_status: 'approved',
        context_window: 32768, max_output_tokens: 4096, knowledge_cutoff: null, description: null }],
      turns_last_day: [{ terminal_state: 'completed', turns: 12 }],
      timeline: [{ scope_kind: 'tool', scope_key: 'record.delete', enabled: false, cause: 'manual',
        reason: 'incident', changed_at: '2026-10-14T00:00:00Z' }],
    })) };
    TestBed.configureTestingModule({
      imports: [AiStatusComponent],
      providers: [
        { provide: ApiService, useValue: api },
        { provide: LangService, useValue: { translate: (key: string) => key, intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(AiStatusComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    expect(api.get).toHaveBeenCalledWith('/api/v1/admin/ai/status');
    expect(el.querySelector('.st-headline')?.getAttribute('data-state')).toBe('degraded');
    expect(el.querySelector('[data-card="m1"]')?.textContent).toContain('Qwen3');
    expect(el.textContent).toContain('completed');
    expect(el.textContent).toContain('record.delete');
  });
});
