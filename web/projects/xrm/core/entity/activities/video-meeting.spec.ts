import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../services/entity.service';
import { ActivitiesPanelComponent } from './activities-panel.component';
import { VideoMeetingService, canJoin, meetingFields, meetingRequest, safeJoinUrl } from './video-meeting';

const START = '2026-11-02T09:00:00Z';
const at = (iso: string) => Date.parse(iso);

describe('video meeting helpers (J7-T2)', () => {
  it('builds the meeting from the start time and length', () => {
    const req = meetingRequest('zoom', 'Kick-off', '2026-11-02T09:00', 45);
    expect(req?.provider).toBe('zoom');
    expect(req?.subject).toBe('Kick-off');
    expect(Date.parse(req!.end) - Date.parse(req!.start)).toBe(45 * 60_000);
    expect(meetingRequest('teams', 'x', '2026-11-02T09:00')!.end)
      .toBe(new Date(Date.parse(meetingRequest('teams', 'x', '2026-11-02T09:00')!.start) + 30 * 60_000).toISOString());
    expect(meetingRequest('meet', 'x', '')).toBeNull();
    expect(meetingRequest('meet', 'x', 'not a date')).toBeNull();
  });

  it('keeps the created meeting on the activity', () => {
    expect(meetingFields({ provider: 'teams', id: 'm-1', join_url: 'https://teams.example/j/1' }, 30)).toEqual({
      meeting_provider: 'teams', meeting_id: 'm-1', meeting_url: 'https://teams.example/j/1', duration_minutes: 30,
    });
  });

  it('shows join only for a web link, from 15 minutes before until the end', () => {
    expect(safeJoinUrl('javascript:alert(1)')).toBeNull();
    expect(safeJoinUrl('not a url')).toBeNull();
    expect(safeJoinUrl('https://meet.jit.si/room')).toBe('https://meet.jit.si/room');
    const row = { status: 'open', meeting_url: 'https://zoom.example/j/9', due_at: START, duration_minutes: 30 };
    expect(canJoin(row, at('2026-11-02T08:40:00Z'))).toBe(false);
    expect(canJoin(row, at('2026-11-02T08:46:00Z'))).toBe(true);
    expect(canJoin(row, at('2026-11-02T09:29:00Z'))).toBe(true);
    expect(canJoin(row, at('2026-11-02T09:31:00Z'))).toBe(false);
    expect(canJoin({ ...row, status: 'completed' }, at(START))).toBe(false);
    expect(canJoin({ ...row, meeting_url: null }, at(START))).toBe(false);
    expect(canJoin({ ...row, due_at: null }, at(START))).toBe(true);
  });
});

describe('ActivitiesPanelComponent video meetings (J7-T2)', () => {
  let svc: { list: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn>; update: ReturnType<typeof vi.fn> };
  let meetings: { create: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    const soon = new Date(Date.now() + 5 * 60_000).toISOString();
    svc = {
      list: vi.fn().mockReturnValue(of({
        data: [
          { id: 'm1', row_version: 1, data: {
            subject: 'Demo', activity_type: 'meeting', status: 'open', due_at: soon,
            meeting_url: 'https://teams.example/j/1', meeting_provider: 'teams', duration_minutes: 30,
          } },
          { id: 't1', row_version: 1, data: { subject: 'Follow up', activity_type: 'task', status: 'open' } },
        ],
        meta: { total: 2, limit: 200, offset: 0 },
      })),
      create: vi.fn().mockReturnValue(of({ id: 'n1', row_version: 0, data: {} })),
      update: vi.fn(),
    };
    meetings = { create: vi.fn().mockReturnValue(of({ provider: 'zoom', id: 'z-9', join_url: 'https://zoom.example/j/9' })) };
    TestBed.configureTestingModule({
      imports: [ActivitiesPanelComponent],
      providers: [
        { provide: EntityService, useValue: svc },
        { provide: VideoMeetingService, useValue: meetings },
        { provide: LangService, useValue: { translate: (key: string) => key } },
      ],
    });
  });

  function render() {
    const fixture = TestBed.createComponent(ActivitiesPanelComponent);
    fixture.componentRef.setInput('entityName', 'contact');
    fixture.componentRef.setInput('recordId', 'rec-1');
    fixture.detectChanges();
    return fixture;
  }

  it('shows a join button on a meeting that is about to start, and none on a task', () => {
    const el: HTMLElement = render().nativeElement;
    const joins = el.querySelectorAll<HTMLAnchorElement>('[data-testid="activities-join"]');
    expect(joins.length).toBe(1);
    expect(joins[0].href).toBe('https://teams.example/j/1');
    expect(joins[0].rel).toContain('noopener');
    expect(el.textContent).toContain('activitiesPanel.videoMeeting');
  });

  it('creates the online meeting first, then the activity with its link', () => {
    const fixture = render();
    const panel = fixture.componentInstance;
    panel.newType = 'meeting';
    panel.newSubject = 'Kick-off';
    panel.newProvider = 'zoom';
    panel.newMinutes = 45;
    expect(panel.canAdd()).toBe(false);
    panel.newDueAt = '2026-11-02T09:00';
    expect(panel.canAdd()).toBe(true);
    panel.add();
    expect(meetings.create).toHaveBeenCalledWith(expect.objectContaining({ provider: 'zoom', subject: 'Kick-off' }));
    expect(svc.create).toHaveBeenCalledWith('activity', expect.objectContaining({
      activity_type: 'meeting', entity_name: 'contact', record_id: 'rec-1',
      meeting_provider: 'zoom', meeting_id: 'z-9', meeting_url: 'https://zoom.example/j/9', duration_minutes: 45,
    }));
  });
});
