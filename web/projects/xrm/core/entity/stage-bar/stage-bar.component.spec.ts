import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { StageBarComponent, StageProcessView, missingFor } from './stage-bar.component';

const PROCESS: StageProcessView = {
  id: 'p-1', name: 'Pipeline', entity: 'opportunity',
  stages: [
    { code: 'qualify', label_en: 'Qualify', required: ['budget'], checklist: ['Call the buyer'], next: ['propose', 'lost'] },
    { code: 'propose', label_en: 'Propose', label_ar: 'عرض', required: ['amount', 'close_date'], next: ['won', 'lost'] },
    { code: 'won', label_en: 'Won' },
    { code: 'lost', label_en: 'Lost' },
  ],
};

describe('StageBarComponent (M7-T2)', () => {
  function create(values: Record<string, unknown>, fail = false) {
    const get = vi.fn((_url: string) => fail ? throwError(() => ({ status: 404, message: 'nf' })) : of(PROCESS));
    TestBed.configureTestingModule({
      imports: [StageBarComponent],
      providers: [
        { provide: ApiService, useValue: { get } },
        { provide: LangService, useValue: { translate: (k: string) => k, current: signal('en'), intlLocale: () => 'en-US' } },
      ],
    });
    const fixture = TestBed.createComponent(StageBarComponent);
    fixture.componentRef.setInput('entityName', 'opportunity');
    fixture.componentRef.setInput('values', values);
    fixture.detectChanges();
    return { fixture, get };
  }

  it('shows the stages with the current one marked', () => {
    const { fixture, get } = create({ stage: 'qualify', budget: 1000 });
    expect(get).toHaveBeenCalledWith('/api/v1/stage-processes/for/opportunity');
    const current: HTMLElement | null = fixture.nativeElement.querySelector('[aria-current="step"]');
    expect(current?.getAttribute('data-stage')).toBe('qualify');
    expect(fixture.nativeElement.textContent).toContain('Call the buyer');
  });

  it('names the required fields a next stage still needs and disables it', () => {
    const { fixture } = create({ stage: 'qualify', amount: 900 });
    const propose: HTMLElement = fixture.nativeElement.querySelector('[data-next="propose"]');
    expect((propose.querySelector('button') as HTMLButtonElement).disabled).toBe(true);
    expect(propose.textContent).toContain('stageBar.missing');
    const lost: HTMLElement = fixture.nativeElement.querySelector('[data-next="lost"]');
    expect((lost.querySelector('button') as HTMLButtonElement).disabled).toBe(false);
  });

  it('emits the chosen next stage', () => {
    const { fixture } = create({ stage: 'qualify', amount: 900, close_date: '2026-11-01' });
    const chosen: string[] = [];
    fixture.componentInstance.choose.subscribe(code => chosen.push(code));
    (fixture.nativeElement.querySelector('[data-next="propose"] button') as HTMLButtonElement).click();
    expect(chosen).toEqual(['propose']);
  });

  it('renders nothing for an entity without a stage process', () => {
    const { fixture } = create({}, true);
    expect(fixture.nativeElement.querySelector('.sb')).toBeNull();
    expect(fixture.nativeElement.querySelector('[role="alert"]')).toBeNull();
  });

  it('finds the empty required fields', () => {
    expect(missingFor(PROCESS.stages[1], { amount: 0, close_date: ' ' })).toEqual(['close_date']);
    expect(missingFor(PROCESS.stages[2], {})).toEqual([]);
  });
});
