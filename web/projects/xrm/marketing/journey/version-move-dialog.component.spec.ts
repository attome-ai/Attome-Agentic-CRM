import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { VersionMoveDialogComponent } from './version-move-dialog.component';
import { JourneyService } from './journey.service';

describe('VersionMoveDialogComponent (E8-T13)', () => {
  const current = signal<'en' | 'ar'>('en');
  const journeys = {
    preview: vi.fn(() => of([
      { node_id: 'reminder', waiting_count: 40, exists_in_new: true, movable_count: 40 },
      { node_id: 'survey', waiting_count: 5, exists_in_new: false, movable_count: 0 },
    ])),
    publish: vi.fn(() => of({ journey_id: 'j1', version_id: 'v3', moved: 40, kept: 5 })),
  };

  beforeEach(() => {
    current.set('en');
    vi.clearAllMocks();
    TestBed.configureTestingModule({
      imports: [VersionMoveDialogComponent],
      providers: [
        { provide: JourneyService, useValue: journeys },
        {
          provide: LangService,
          useValue: { current, translate: (k: string) => k, isRtl: () => current() === 'ar', intlLocale: () => 'en' },
        },
      ],
    });
  });

  function render(done: (result: unknown) => void) {
    const fixture = TestBed.createComponent(VersionMoveDialogComponent);
    fixture.componentRef.setInput('journeyId', 'j1');
    fixture.componentRef.setInput('versionId', 'v3');
    fixture.componentRef.setInput('done', done);
    fixture.detectChanges();
    return fixture;
  }

  it('shows who waits where and publishes with the choice made', async () => {
    let outcome: unknown = 'none';
    const fixture = render(result => (outcome = result));
    const root: HTMLElement = fixture.nativeElement;
    expect(journeys.preview).toHaveBeenCalledWith('j1', 'v3');
    expect(root.querySelectorAll('[data-testid="vm-row"]').length).toBe(2);
    expect(fixture.componentInstance.movable()).toBe(40);

    const move = root.querySelector('[data-testid="vm-move"]') as HTMLInputElement;
    move.click();
    fixture.detectChanges();
    await fixture.whenStable();
    (root.querySelector('[data-testid="vm-publish"]') as HTMLButtonElement).click();
    expect(journeys.publish).toHaveBeenCalledWith('j1', 'v3', 'move_matching');
    expect(outcome).toEqual({ journey_id: 'j1', version_id: 'v3', moved: 40, kept: 5 });
  });

  it('publishes keeping everyone on their version by default, and cancels with nothing', () => {
    let outcome: unknown = 'none';
    const fixture = render(result => (outcome = result));
    const root: HTMLElement = fixture.nativeElement;
    (root.querySelector('[data-testid="vm-cancel"]') as HTMLButtonElement).click();
    expect(outcome).toBeNull();
    expect(journeys.publish).not.toHaveBeenCalled();
    fixture.componentInstance.publish();
    expect(journeys.publish).toHaveBeenCalledWith('j1', 'v3', 'finish_on_old');
  });

  it('renders right to left in Arabic, numbers left to right', () => {
    current.set('ar');
    const fixture = render(() => undefined);
    const root: HTMLElement = fixture.nativeElement;
    expect(root.querySelector('[data-testid="vm"]')?.getAttribute('dir')).toBe('rtl');
    const cells = [...root.querySelectorAll('[data-testid="vm-row"] td[dir="ltr"]')].map(c => c.textContent?.trim());
    expect(cells).toEqual(['40', '40', '5', '0']);
  });
});
