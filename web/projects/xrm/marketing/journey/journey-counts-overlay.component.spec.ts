import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { COUNTS_POLL_MS, JourneyCountsOverlayComponent, countsFor } from './journey-counts-overlay.component';
import { JourneyCounts, JourneyService } from './journey.service';

const COUNTS: JourneyCounts = {
  definition_id: 'd1',
  enrolled: 1500,
  converted: 30,
  conversion: 0.02,
  nodes: [
    { definition_version_id: 'v1', node_id: 'welcome', entered: 900, waiting: 0, passed: 900, blocked: 0, exited: 0 },
    { definition_version_id: 'v2', node_id: 'welcome', entered: 1200, waiting: 3, passed: 1190, blocked: 7, exited: 0 },
    { definition_version_id: 'v2', node_id: 'reminder', entered: 400, waiting: 40, passed: 300, blocked: 0, exited: 60 },
  ],
};

describe('JourneyCountsOverlayComponent (E8-T13)', () => {
  const current = signal<'en' | 'ar'>('en');
  const journeys = { counts: vi.fn(() => of(COUNTS)) };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    vi.useFakeTimers();
    TestBed.configureTestingModule({
      imports: [JourneyCountsOverlayComponent],
      providers: [
        { provide: JourneyService, useValue: journeys },
        {
          provide: LangService,
          useValue: { current, translate: (k: string) => k, isRtl: () => current() === 'ar', intlLocale: () => 'en' },
        },
      ],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render(version: string | null) {
    const fixture = TestBed.createComponent(JourneyCountsOverlayComponent);
    fixture.componentRef.setInput('journeyId', 'j1');
    fixture.componentRef.setInput('versionId', version);
    fixture.componentRef.setInput('nodes', [
      { id: 'welcome', ports: { x: 40, y: 100 } },
      { id: 'reminder', ports: { x: 260, y: 100 } },
      { id: 'goal', ports: { x: 480, y: 100 } },
    ]);
    fixture.detectChanges();
    return fixture;
  }

  it("takes the version's own counts, else the newest version's", () => {
    expect(countsFor(COUNTS, 'v1').get('welcome')?.entered).toBe(900);
    expect(countsFor(COUNTS, 'draft').get('welcome')?.entered).toBe(1200);
    expect(countsFor(null, 'v1').size).toBe(0);
  });

  it('draws each counted node above it, and reads the counts again every ten seconds', () => {
    const fixture = render('v2');
    const root: HTMLElement = fixture.nativeElement;
    const badges = root.querySelectorAll<HTMLElement>('[data-testid="jc"]');
    expect(badges.length).toBe(2);
    expect(badges[0].style.left).toBe('40px');
    expect(badges[0].style.top).toBe('78px');
    expect(badges[0].textContent).toContain('1,200');
    expect(badges[1].textContent).toContain('60');
    expect(journeys.counts).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(COUNTS_POLL_MS);
    expect(journeys.counts).toHaveBeenCalledTimes(2);
  });

  it('outlines the highlighted node and renders right to left in Arabic', () => {
    current.set('ar');
    const fixture = render('v2');
    fixture.componentRef.setInput('highlight', 'reminder');
    fixture.detectChanges();
    const badges = (fixture.nativeElement as HTMLElement).querySelectorAll<HTMLElement>('[data-testid="jc"]');
    expect(badges[0].getAttribute('dir')).toBe('rtl');
    expect(badges[1].classList.contains('jc-on')).toBe(true);
    expect(badges[0].classList.contains('jc-on')).toBe(false);
  });
});
