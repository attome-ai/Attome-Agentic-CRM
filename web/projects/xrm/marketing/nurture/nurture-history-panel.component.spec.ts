import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { NurtureHistoryPanelComponent } from './nurture-history-panel.component';
import { NurtureHistory, NurtureService } from './nurture.service';

const HISTORY: NurtureHistory = {
  person_id: 'c1',
  states: [{ program_id: 'p1', status: 'handed_off', position: 2 }],
  content_seen: [{ content_kind: 'email', content_id: 'd1', first_seen_at: '2026-11-01T08:00:00Z' }],
  handoffs: [
    { id: 'h2', program_id: 'p1', person_id: 'c1', status: 'pending', created_at: '2026-11-02T08:00:00Z' },
    { id: 'h1', program_id: 'p1', person_id: 'c1', status: 'returned', return_reason: 'no budget',
      created_at: '2026-10-01T08:00:00Z' },
  ],
};

describe('NurtureHistoryPanelComponent (E9-T11)', () => {
  const current = signal<'en' | 'ar'>('en');
  const nurture = { history: vi.fn(), accept: vi.fn(), returnHandoff: vi.fn() };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    TestBed.configureTestingModule({
      imports: [NurtureHistoryPanelComponent],
      providers: [
        { provide: NurtureService, useValue: nurture },
        {
          provide: LangService,
          useValue: {
            current,
            translate: (k: string) => k,
            isRtl: () => current() === 'ar',
            intlLocale: () => 'en-US',
          },
        },
      ],
    });
  });

  function render(entity = 'lead') {
    const fixture = TestBed.createComponent(NurtureHistoryPanelComponent);
    fixture.componentRef.setInput('entityName', entity);
    fixture.componentRef.setInput('recordId', 'c1');
    fixture.detectChanges();
    return fixture;
  }

  it('lists programmes, content seen and hand-offs, with the open hand-off to decide', () => {
    nurture.history.mockReturnValue(of(HISTORY));
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(nurture.history).toHaveBeenCalledWith('c1', 'lead');
    expect(root.querySelector('[data-testid="nh-states"]')?.textContent).toContain('nurturePanel.status.handed_off');
    expect(root.querySelector('[data-testid="nh-seen"]')?.textContent).toContain('d1');
    expect(root.querySelector('[data-testid="nh-handoffs"]')?.textContent).toContain('no budget');
    expect(fixture.componentInstance.open()?.id).toBe('h2');
    expect(root.querySelector('[data-testid="hp"]')).not.toBeNull();
  });

  it('says so, right to left in Arabic, when the history cannot be read', () => {
    current.set('ar');
    nurture.history.mockReturnValue(throwError(() => new Error('404')));
    const fixture = render('contact');
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="nh"]')?.getAttribute('dir')).toBe('rtl');
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('nurturePanel.historyFailed');
  });
});
