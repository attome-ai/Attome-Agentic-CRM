import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { ModelService } from '../model.service';
import { OptionSetEditorComponent, contrast, contrastFailures } from './option-set-editor.component';

describe('OptionSetEditorComponent (A5-T4)', () => {
  it('measures contrast and names the themes a colour fails', () => {
    expect(contrast('#000000', '#ffffff')).toBeCloseTo(21, 0);
    expect(contrastFailures('#ffff00')).toContain('light');
    expect(contrastFailures('#000080')).toContain('dark');
    expect(contrastFailures(undefined)).toEqual([]);
  });

  it('saves a new set as a draft with its cleaned values', () => {
    const saveDraft = vi.fn().mockReturnValue(of({ id: 'x', version_no: 1, content_hash: 'h1', issues: [] }));
    TestBed.configureTestingModule({
      imports: [OptionSetEditorComponent],
      providers: [
        { provide: ModelService, useValue: {
          objects: vi.fn().mockReturnValue(of({ items: [], total: 0, page: 1, page_size: 50 })),
          saveDraft,
          publish: vi.fn(),
          object: vi.fn(),
        } },
        { provide: LangService, useValue: { translate: (k: string) => k } },
      ],
    });
    const fixture = TestBed.createComponent(OptionSetEditorComponent);
    fixture.detectChanges();
    const c = fixture.componentInstance;
    c.startNew();
    c.name.set('deal_stage');
    c.update(0, 'code', ' open ');
    c.update(0, 'label_en', 'Open');
    c.update(0, 'label_ar', '');
    c.save();
    const [kind, , baseHash, name, commands] = saveDraft.mock.calls[0];
    expect(kind).toBe('option_set');
    expect(baseHash).toBe('');
    expect(name).toBe('deal_stage');
    expect(commands).toEqual([{ op: 'set', path: '/values', value: [{ code: 'open', label_en: 'Open', order: 1 }] }]);
    expect(c.hash()).toBe('h1');
  });
});
