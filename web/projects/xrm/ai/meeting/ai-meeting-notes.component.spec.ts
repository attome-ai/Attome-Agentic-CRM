import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { ApiService, LangService } from '@attome/base';
import { of } from 'rxjs';
import { describe, expect, it, vi } from 'vitest';

import { AiMeetingNotesComponent, valueText } from './ai-meeting-notes.component';
import { checkedIndexes, parseNotesItems, toMeetingNotes } from './ai-meeting.service';

const RECORD = {
  id: 'n1',
  row_version: 3,
  data: {
    meeting_id: 'm1',
    status: 'draft',
    language: 'ar',
    summary: 'اتفاق على التجديد',
    decisions: 'التجديد لمدة سنتين\n\nإضافة التدريب',
    action_items_json: JSON.stringify({
      action_items: [
        { text: 'إرسال عرض السعر', owner_hint: 'سارة', due_hint: '2027-03-04' },
        { text: 'حجز جلسة الإعداد', owner_hint: null, due_hint: null },
        { text: 'مشاركة نموذج البيانات' },
      ],
      record_updates: [
        { entity: 'opportunity', record_id: 'o1', attribute: 'amount', value: 5000, quote: 'خمسة آلاف' },
        { entity: 'opportunity', record_id: 'o1', attribute: 'stage', value: 'proposal', quote: 'نرسل العرض' },
      ],
    }),
  },
};

describe('AiMeetingNotesComponent (AI6-T7)', () => {
  function create() {
    const get = vi.fn((_: string) => of(RECORD));
    const post = vi.fn((_: string, __: unknown, ___?: unknown) => of({ status: 'completed', result: {} }));
    TestBed.configureTestingModule({
      imports: [AiMeetingNotesComponent],
      providers: [
        { provide: ApiService, useValue: { get, post } },
        {
          provide: LangService,
          useValue: { translate: (k: string) => k, current: signal('en'), errorText: () => 'error', intlLocale: () => 'en-US' },
        },
      ],
    });
    const fixture = TestBed.createComponent(AiMeetingNotesComponent);
    fixture.componentRef.setInput('meetingId', 'm1');
    fixture.componentRef.setInput('notesId', 'n1');
    fixture.detectChanges();
    return { fixture, get, post };
  }

  it('reads the notes and runs them right to left in Arabic', () => {
    const { fixture, get } = create();
    expect(get).toHaveBeenCalledWith('/api/v1/ai_meeting_notes/n1');
    const el = fixture.nativeElement as HTMLElement;
    expect(el.querySelector('.amn-body')?.getAttribute('dir')).toBe('rtl');
    expect(el.querySelectorAll('input[data-item]').length).toBe(3);
    expect(el.querySelector('[data-quote="0"]')?.textContent).toContain('خمسة آلاف');
  });

  it('sends only the checked items on confirm', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    // Every action item starts checked and every update unchecked: drop the
    // second item, choose the second update.
    c.toggleItem(1);
    c.toggleUpdate(1);
    c.confirm();
    expect(post).toHaveBeenCalledWith(
      '/api/v1/ai/meetings/m1/notes/confirm',
      { notes_id: 'n1', action_item_indexes: [0, 2], record_update_indexes: [1] },
      { ifMatch: 3 },
    );
  });

  it('sends nothing unchosen when everything is unchecked', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    [0, 1, 2].forEach(i => c.toggleItem(i));
    c.confirm();
    expect(post).toHaveBeenCalledWith(
      '/api/v1/ai/meetings/m1/notes/confirm',
      { notes_id: 'n1', action_item_indexes: [], record_update_indexes: [] },
      { ifMatch: 3 },
    );
  });

  it('asks for notes from a recording', () => {
    const { fixture, post } = create();
    const c = fixture.componentInstance;
    c.transcriptRef = ' doc-7 ';
    c.requestNotes();
    expect(post).toHaveBeenCalledWith('/api/v1/ai/meetings/m1/notes', { transcript_ref: 'doc-7' });
  });

  it('reads the stored items and decisions', () => {
    const notes = toMeetingNotes(RECORD);
    expect(notes.decisions).toEqual(['التجديد لمدة سنتين', 'إضافة التدريب']);
    expect(notes.action_items.length).toBe(3);
    expect(parseNotesItems('not json')).toEqual({ action_items: [], record_updates: [] });
    expect(parseNotesItems(null)).toEqual({ action_items: [], record_updates: [] });
    expect(checkedIndexes([true, false, true])).toEqual([0, 2]);
    expect(valueText(5000)).toBe('5000');
    expect(valueText('proposal')).toBe('proposal');
  });
});
