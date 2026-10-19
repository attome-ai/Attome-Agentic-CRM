import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EntityService } from '../services/entity.service';
import { VideoMeetingService } from './video-meeting';
import {
  ActivitiesPanelComponent, ActivityRow, CallLog, callBody, isOverdue, nextStepBody, sortActivities,
} from './activities-panel.component';

const PAST = '2020-01-01T09:00:00Z';
const FUTURE = '2999-01-01T09:00:00Z';

function row(partial: Partial<ActivityRow> & { id: string }): ActivityRow {
  return {
    subject: partial.id, activity_type: 'task', status: 'open',
    due_at: null, completed_at: null, direction: null, row_version: 1,
    ...partial,
  };
}

describe('sortActivities / isOverdue', () => {
  it('puts open activities first, earliest due first and undated last', () => {
    const sorted = sortActivities([
      row({ id: 'done', status: 'completed', completed_at: PAST }),
      row({ id: 'undated' }),
      row({ id: 'later', due_at: FUTURE }),
      row({ id: 'sooner', due_at: PAST }),
    ]);
    expect(sorted.map(r => r.id)).toEqual(['sooner', 'later', 'undated', 'done']);
  });

  it('flags only an open activity whose due time has passed', () => {
    expect(isOverdue(row({ id: 'a', due_at: PAST }))).toBe(true);
    expect(isOverdue(row({ id: 'b', due_at: FUTURE }))).toBe(false);
    expect(isOverdue(row({ id: 'c' }))).toBe(false);
    expect(isOverdue(row({ id: 'd', due_at: PAST, status: 'completed' }))).toBe(false);
  });
});

describe('callBody / nextStepBody (D14-T2)', () => {
  const log: CallLog = {
    subject: 'Discovery call', direction: 'inbound', minutes: 12, notes: '  budget agreed ',
    outcome: 'interested', nextSubject: 'Send proposal', nextDue: '2026-11-02T10:00',
  };

  it('builds a phone call on the record with only the given extras', () => {
    expect(callBody(log, 'account', 'r-1')).toEqual({
      subject: 'Discovery call', activity_type: 'phone_call', direction: 'inbound',
      entity_name: 'account', record_id: 'r-1', duration_minutes: 12,
      description: 'budget agreed', outcome: 'interested',
    });
    const bare = callBody({ ...log, minutes: null, notes: ' ', outcome: '' }, 'account', 'r-1');
    expect(bare).not.toHaveProperty('duration_minutes');
    expect(bare).not.toHaveProperty('description');
    expect(bare).not.toHaveProperty('outcome');
  });

  it('makes a next-step task only when one is named', () => {
    const task = nextStepBody(log, 'account', 'r-1')!;
    expect(task['activity_type']).toBe('task');
    expect(task['subject']).toBe('Send proposal');
    expect(typeof task['due_at']).toBe('string');
    expect(nextStepBody({ ...log, nextSubject: ' ' }, 'account', 'r-1')).toBeNull();
  });
});

describe('ActivitiesPanelComponent', () => {
  let svc: { list: ReturnType<typeof vi.fn>; create: ReturnType<typeof vi.fn>; update: ReturnType<typeof vi.fn> };

  const listed = [
    { id: 'c1', row_version: 3, data: { subject: 'Closed one', activity_type: 'task', status: 'completed', completed_at: PAST } },
    { id: 'o1', row_version: 2, data: { subject: 'Late call', activity_type: 'phone_call', status: 'open', due_at: PAST } },
  ];

  beforeEach(() => {
    svc = {
      list: vi.fn().mockReturnValue(of({ data: listed, meta: { total: 2, limit: 200, offset: 0 } })),
      create: vi.fn().mockReturnValue(of({ id: 'n1', row_version: 0, data: {} })),
      update: vi.fn().mockReturnValue(of({ id: 'o1', row_version: 3, data: {} })),
    };
    TestBed.configureTestingModule({
      imports: [ActivitiesPanelComponent],
      providers: [
        { provide: EntityService, useValue: svc },
        { provide: VideoMeetingService, useValue: { create: vi.fn() } },
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

  it("lists the record's activities, open first, with the overdue one highlighted", () => {
    const fixture = render();
    expect(svc.list).toHaveBeenCalledWith('activity', expect.objectContaining({
      filters: [
        { field: 'entity_name', op: 'eq', value: 'contact' },
        { field: 'record_id', op: 'eq', value: 'rec-1' },
      ],
    }));
    const el: HTMLElement = fixture.nativeElement;
    const rows = Array.from(el.querySelectorAll<HTMLElement>('[data-testid="activities-row"]'));
    expect(rows.map(r => r.querySelector('.act-subject-text')?.textContent?.trim())).toEqual(['Late call', 'Closed one']);
    expect(rows[0].classList).toContain('act-overdue');
    expect(rows[0].querySelector('[data-testid="activities-overdue"]')).not.toBeNull();
    expect(rows[0].querySelector('[data-testid="activities-complete"]')).not.toBeNull();
    expect(rows[1].querySelector('[data-testid="activities-complete"]')).toBeNull();
  });

  it('quick-creates a phone call on this record through the generic create', () => {
    const fixture = render();
    const cmp = fixture.componentInstance;
    cmp.newType = 'phone_call';
    cmp.newSubject = '  Call back  ';
    cmp.newDirection = 'inbound';
    cmp.add();
    expect(svc.create).toHaveBeenCalledWith('activity', {
      subject: 'Call back',
      activity_type: 'phone_call',
      direction: 'inbound',
      entity_name: 'contact',
      record_id: 'rec-1',
    });
    expect(svc.list).toHaveBeenCalledTimes(2);
    expect(cmp.newSubject).toBe('');
  });

  it('does not create an activity without a subject', () => {
    const fixture = render();
    fixture.componentInstance.newSubject = '   ';
    fixture.componentInstance.add();
    expect(svc.create).not.toHaveBeenCalled();
  });

  it('completes an open activity with a status PATCH carrying its row_version', () => {
    const fixture = render();
    const el: HTMLElement = fixture.nativeElement;
    el.querySelector<HTMLButtonElement>('[data-testid="activities-complete"]')!.click();
    expect(svc.update).toHaveBeenCalledWith(
      'activity', 'o1',
      { status: 'completed', completed_at: expect.any(String) },
      2,
    );
    expect(svc.list).toHaveBeenCalledTimes(2);
  });
});
