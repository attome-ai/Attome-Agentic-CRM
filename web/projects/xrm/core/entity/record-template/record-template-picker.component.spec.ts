import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { OfferedTemplate, RecordTemplatePickerComponent, missingAnswers } from './record-template-picker.component';

const RENEWAL: OfferedTemplate = {
  id: 'tpl-1',
  label_en: 'Enterprise renewal',
  label_ar: 'تجديد مؤسسي',
  prompts: [
    { field: 'seats', label_en: 'Seats', label_ar: null, required: true },
    { field: 'note', label_en: 'Note', label_ar: null, required: false },
  ],
  children: 0,
};

describe('RecordTemplatePickerComponent (B8-T3)', () => {
  function create(templates: OfferedTemplate[]) {
    TestBed.resetTestingModule();
    const get = vi.fn((_url: string, _params?: Record<string, string>) =>
      of({ items: templates, total: templates.length, page: 1, page_size: 20 }));
    const post = vi.fn((_url: string, _body: unknown) => of({ entity: 'opportunity', id: 'rec-9', children: [] }));
    const navigate = vi.fn(() => Promise.resolve(true));
    TestBed.configureTestingModule({
      imports: [RecordTemplatePickerComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        { provide: Router, useValue: { navigate } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, errorText: () => 'error', current: signal('en') },
        },
      ],
    });
    const fixture = TestBed.createComponent(RecordTemplatePickerComponent);
    fixture.componentRef.setInput('entity', 'opportunity');
    fixture.detectChanges();
    return { fixture, get, post, navigate };
  }

  it('shows nothing when no template is offered', () => {
    const { fixture, get } = create([]);
    expect(get).toHaveBeenCalledWith('/api/v1/record-templates', { entity: 'opportunity' });
    expect(fixture.nativeElement.querySelector('[data-testid="rtp-open"]')).toBeNull();
  });

  it('asks the required prompts before creating, then opens the record', () => {
    const { fixture, post, navigate } = create([RENEWAL]);
    (fixture.nativeElement.querySelector('[data-testid="rtp-open"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    (fixture.nativeElement.querySelector('[data-testid="rtp-template"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    const createButton: HTMLButtonElement = fixture.nativeElement.querySelector('[data-testid="rtp-create"]');
    createButton.click();
    fixture.detectChanges();
    expect(post).not.toHaveBeenCalled();
    expect(fixture.nativeElement.querySelector('[data-testid="rtp-error"]')).not.toBeNull();

    fixture.componentInstance.answers['seats'] = '25';
    createButton.click();
    fixture.detectChanges();
    expect(post).toHaveBeenCalledWith('/api/v1/record-templates/tpl-1/create', { answers: { seats: '25' } });
    expect(navigate).toHaveBeenCalled();
  });

  it('lists the missing required answers', () => {
    expect(missingAnswers(RENEWAL, {})).toEqual(['seats']);
    expect(missingAnswers(RENEWAL, { seats: '  ' })).toEqual(['seats']);
    expect(missingAnswers(RENEWAL, { seats: '3' })).toEqual([]);
  });
});
