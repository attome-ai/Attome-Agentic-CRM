import { ComponentFixture, TestBed } from '@angular/core/testing';
import { signal } from '@angular/core';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';
import { LangService } from '@attome/base';
import { CallPageComponent, CallintelService, clock } from './call-page.component';
import type { CallPage } from './call-page.component';

const PAGE: CallPage = {
  activity_id: 'a1', analysis_id: 'n1', status: 'done', talk: null,
  findings: [{ id: 'f1', kind: 'objection', text: 'Too expensive', start_ms: 65_000, task_ref: null }],
  scorecard: [],
  transcript: [
    { start_ms: 1000, speaker: 'customer', text: 'السعر مرتفع جدا' },
    { start_ms: 4000, speaker: 'staff', text: 'Let me explain the plans.' },
  ],
};

async function render(rtl: boolean): Promise<ComponentFixture<CallPageComponent>> {
  const svc = {
    page: vi.fn(() => of(PAGE)),
    recording: vi.fn(() => of({ download_url: 'blob:x', expires_in_secs: 60 })),
    comment: vi.fn(), confirm: vi.fn(), task: vi.fn(),
  };
  await TestBed.configureTestingModule({
    imports: [CallPageComponent],
    providers: [
      { provide: CallintelService, useValue: svc },
      {
        provide: LangService,
        useValue: {
          translate: (key: string) => key,
          errorText: () => 'errors.unknown',
          intlLocale: () => (rtl ? 'ar-SA' : 'en-US'),
          isRtl: signal(rtl),
        },
      },
    ],
  }).compileComponents();
  const fixture = TestBed.createComponent(CallPageComponent);
  fixture.componentRef.setInput('activityId', 'a1');
  fixture.detectChanges();
  await fixture.whenStable();
  fixture.detectChanges();
  return fixture;
}

describe('CallPageComponent', () => {
  it('clicking a highlight seeks the player', async () => {
    const fixture = await render(false);
    const audio: HTMLAudioElement = fixture.nativeElement.querySelector('[data-testid="player"]');
    fixture.nativeElement.querySelector('[data-testid="highlight"]').click();
    expect(audio.currentTime).toBe(65);
    expect(clock(65_000)).toBe('1:05');
  });

  it('Arabic transcript renders right to left', async () => {
    TestBed.resetTestingModule();
    const fixture = await render(true);
    expect(fixture.nativeElement.getAttribute('dir')).toBe('rtl');
    const lines = fixture.nativeElement.querySelectorAll('[data-testid="segment"]');
    expect(lines.length).toBe(2);
    expect(lines[0].getAttribute('dir')).toBe('auto');
  });
});
