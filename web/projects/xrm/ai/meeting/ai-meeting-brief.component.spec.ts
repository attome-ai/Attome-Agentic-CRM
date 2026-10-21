import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of, throwError } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiMeetingBriefComponent, textDir } from './ai-meeting-brief.component';

const BRIEF = {
  id: 'b1', meeting_id: 'm1', status: 'ready', language: 'ar',
  brief_text: 'هدف الاجتماع: مراجعة التجديد', generated_at: '2027-03-01T08:00:00Z', row_version: 2,
};

describe('AiMeetingBriefComponent (AI6-T7)', () => {
  function create(get: (path: string) => unknown = vi.fn((_: string) => of(BRIEF))) {
    const post = vi.fn((_: string, __: unknown) => of({ status: 'approval_required' }));
    TestBed.configureTestingModule({
      imports: [AiMeetingBriefComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), errorText: () => 'error' },
        },
      ],
    });
    const fixture = TestBed.createComponent(AiMeetingBriefComponent);
    fixture.componentRef.setInput('meetingId', 'm1');
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('shows the brief in its own direction', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/ai/meetings/m1/brief');
    const text = (fixture.nativeElement as HTMLElement).querySelector('[data-brief-text]');
    expect(text?.getAttribute('dir')).toBe('rtl');
    expect(text?.textContent).toContain('مراجعة التجديد');
  });

  it('treats no brief yet as no error', () => {
    const { fixture } = create(vi.fn(() => throwError(() => ({ kind: 'not_found', status: 404, message: '' }))));
    expect(fixture.componentInstance.error()).toBeNull();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('aiMeeting.brief.none');
  });

  it('regenerates and says when the brief waits', () => {
    const { fixture, post } = create();
    fixture.componentInstance.regenerate();
    expect(post).toHaveBeenCalledWith('/api/v1/ai/meetings/m1/brief/regenerate', {});
    expect(fixture.componentInstance.pending()).toBe('approval_required');
    expect(textDir('en')).toBe('ltr');
  });
});
