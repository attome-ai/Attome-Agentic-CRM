import { computed, signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';
import { ActiveTour, LangService, Tour, TourService } from '@attome/base';
import { Subject } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { TourOverlayComponent, placeBubble } from './tour-overlay.component';

const TOUR: Tour = {
  id: 't1', name: 't1', route: '/xrm', auto_start: true,
  title: { en: 'Welcome', ar: 'أهلًا' },
  steps: [
    { selector: '#nowhere', text: { en: 'First step', ar: 'الخطوة الأولى' } },
    { selector: '#nowhere', title: { en: 'Two' }, text: { en: 'Second step' } },
  ],
};

describe('TourOverlayComponent (B14-T1)', () => {
  it('places the bubble beside its element and keeps it on screen', () => {
    const viewport = { width: 1000, height: 800 };
    const target = { top: 100, left: 100, width: 50, height: 20 };
    expect(placeBubble(target, 'bottom', false, viewport, 300, 100)).toEqual({ top: 132, left: 100 });
    expect(placeBubble(target, 'end', false, viewport, 300, 100).left).toBe(162);
    // In right-to-left, `end` is the left side, clamped inside the viewport.
    expect(placeBubble(target, 'end', true, viewport, 300, 100).left).toBe(12);
    expect(placeBubble(null, undefined, false, viewport, 300, 100)).toEqual({ top: 350, left: 350 });
  });

  function render(lang = 'en') {
    const active = signal<ActiveTour | null>({ tour: TOUR, step: 0 });
    const tours = {
      active,
      step: computed(() => active()?.tour.steps[active()!.step] ?? null),
      next: vi.fn(() => active.set({ tour: TOUR, step: 1 })),
      back: vi.fn(),
      finish: vi.fn(() => active.set(null)),
      onNavigate: vi.fn(() => Promise.resolve()),
    };
    TestBed.configureTestingModule({
      imports: [TourOverlayComponent],
      providers: [
        { provide: TourService, useValue: tours },
        { provide: Router, useValue: { url: '/xrm', events: new Subject() } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal(lang), isRtl: signal(lang === 'ar') },
        },
      ],
    });
    const fixture = TestBed.createComponent(TourOverlayComponent);
    fixture.detectChanges();
    return { fixture, tours, root: fixture.nativeElement as HTMLElement };
  }

  it('shows the step in the page language and moves on', () => {
    const { fixture, tours, root } = render('ar');
    expect(tours.onNavigate).toHaveBeenCalledWith('/xrm');
    expect(root.querySelector('[data-tour-text]')!.textContent).toContain('الخطوة الأولى');
    expect(root.querySelector('[data-tour-back]')).toBeNull();
    root.querySelector<HTMLButtonElement>('[data-tour-next]')!.click();
    fixture.detectChanges();
    expect(tours.next).toHaveBeenCalled();
    // The second step has no Arabic: its English shows.
    expect(root.querySelector('[data-tour-text]')!.textContent).toContain('Second step');
    expect(root.querySelector('[data-tour-back]')).not.toBeNull();
  });

  it('closing skips the tour', () => {
    const { fixture, tours, root } = render();
    root.querySelector<HTMLButtonElement>('.to-close')!.click();
    fixture.detectChanges();
    expect(tours.finish).toHaveBeenCalled();
    expect(root.querySelector('[data-tour-bubble]')).toBeNull();
  });
});
