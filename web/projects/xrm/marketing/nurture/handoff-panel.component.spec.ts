import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { HandoffPanelComponent, hijriDate } from './handoff-panel.component';
import { Handoff, NurtureService } from './nurture.service';

const HANDOFF: Handoff = {
  id: 'h1',
  program_id: 'p1',
  person_id: 'c1',
  status: 'pending',
  score: 72,
  summary: { score: 72, threshold: 60, content_seen: [{ kind: 'email', id: 'd1' }], next_step: 'call' },
  created_at: '2026-11-02T08:00:00Z',
};

describe('HandoffPanelComponent (E9-T11)', () => {
  const current = signal<'en' | 'ar'>('en');
  const nurture = {
    accept: vi.fn(() => of({ ...HANDOFF, status: 'accepted' })),
    returnHandoff: vi.fn(() => of({ handoff_id: 'h1', recycled: true })),
  };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    TestBed.configureTestingModule({
      imports: [HandoffPanelComponent],
      providers: [
        { provide: NurtureService, useValue: nurture },
        {
          provide: LangService,
          useValue: {
            current,
            translate: (k: string) => k,
            isRtl: () => current() === 'ar',
            intlLocale: () => (current() === 'ar' ? 'ar-SA' : 'en-US'),
          },
        },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(HandoffPanelComponent);
    fixture.componentRef.setInput('handoff', HANDOFF);
    fixture.detectChanges();
    return fixture;
  }

  it('shows the score against the hand-off score and accepts through the route', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="hp-score"]')?.textContent).toContain('72 / 60');
    let changed = 0;
    fixture.componentInstance.changed.subscribe(() => changed++);
    (root.querySelector('[data-testid="hp-accept"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(nurture.accept).toHaveBeenCalledWith('h1');
    expect(changed).toBe(1);
    expect(root.querySelector('[data-testid="hp-done"]')?.textContent).toContain('nurturePanel.accepted');
  });

  it('returns with a reason and a wake-up date, right to left in Arabic with the Hijri date', () => {
    current.set('ar');
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="hp"]')?.getAttribute('dir')).toBe('rtl');
    const c = fixture.componentInstance;
    (c as unknown as { reason: string }).reason = 'not ready';
    c.wake.set('2026-03-01');
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="hp-hijri"]')?.textContent).toMatch(/١٤٤٧|1447/);
    c.giveBack();
    expect(nurture.returnHandoff).toHaveBeenCalledWith('h1', 'not ready', '2026-03-01T00:00:00Z');
  });

  it('reads a date as Umm al-Qura, and nothing else', () => {
    expect(hijriDate('2026-03-01', 'en-US')).toMatch(/1447/);
    expect(hijriDate('not a date', 'en-US')).toBeNull();
  });
});
