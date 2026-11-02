import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { PersonPathComponent } from './person-path.component';
import { JourneyService, PersonRun } from './journey.service';

const RUN: PersonRun = {
  enrolment_id: 'e1',
  status: 'active',
  entered_at: '2026-11-01T08:00:00Z',
  ended_at: null,
  end_reason: null,
  steps: [
    { node_id: 'welcome', status: 'succeeded', started_at: '2026-11-01T08:00:00Z', completed_at: '2026-11-01T08:00:01Z' },
    { node_id: 'reminder', status: 'waiting', started_at: '2026-11-02T08:00:00Z', completed_at: null },
  ],
  blocks: [{ node_id: 'reminder', reason: 'frequency_cap', at: '2026-11-02T08:00:00Z' }],
};

describe('PersonPathComponent (E8-T13)', () => {
  const current = signal<'en' | 'ar'>('en');
  const journeys = { path: vi.fn() };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    TestBed.configureTestingModule({
      imports: [PersonPathComponent],
      providers: [
        { provide: JourneyService, useValue: journeys },
        {
          provide: LangService,
          useValue: { current, translate: (k: string) => k, isRtl: () => current() === 'ar', intlLocale: () => 'en' },
        },
      ],
    });
  });

  function render(stepChanged: (node: string | null) => void) {
    const fixture = TestBed.createComponent(PersonPathComponent);
    fixture.componentRef.setInput('journeyId', 'j1');
    fixture.componentRef.setInput('personId', 'p1');
    fixture.componentRef.setInput('stepChanged', stepChanged);
    fixture.detectChanges();
    return fixture;
  }

  it('replays the run step by step and tells the editor each node', () => {
    journeys.path.mockReturnValue(of([RUN]));
    const seen: (string | null)[] = [];
    const fixture = render(node => seen.push(node));
    const root: HTMLElement = fixture.nativeElement;
    expect(journeys.path).toHaveBeenCalledWith('j1', 'p1');
    expect(root.querySelector('[data-testid="pp-step"]')?.textContent).toContain('welcome');
    expect(root.querySelector('[data-testid="pp-block"]')).toBeNull();

    (root.querySelector('[data-testid="pp-next"]') as HTMLButtonElement).click();
    fixture.detectChanges();
    expect(root.querySelector('[data-testid="pp-step"]')?.textContent).toContain('reminder');
    expect(root.querySelector('[data-testid="pp-block"]')?.textContent).toContain('frequency_cap');
    expect(seen.filter(n => n !== null)).toEqual(['welcome', 'reminder']);
    expect((root.querySelector('[data-testid="pp-next"]') as HTMLButtonElement).disabled).toBe(true);
  });

  it('says so, right to left in Arabic, when the path cannot be read', () => {
    current.set('ar');
    journeys.path.mockReturnValue(throwError(() => new Error('404')));
    const fixture = render(() => undefined);
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="pp"]')?.getAttribute('dir')).toBe('rtl');
    expect(root.querySelector('[role="alert"]')?.textContent).toContain('journeyEditor.pathFailed');
  });
});
