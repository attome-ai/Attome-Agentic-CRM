import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService, LiveChannel, UserPreferencesService } from '@attome/base';
import { RecordTimelinePanelComponent, TIMELINE_PAGE_SIZE, contactGaps } from './record-timeline-panel.component';
import { RecordTimelineService, TimelineEntry, timelineSummary } from './record-timeline.service';

function entry(id: string, kind: TimelineEntry['kind'], summary: string): TimelineEntry {
  return {
    kind,
    occurred_at: '2026-09-23T10:00:00Z',
    source_entity: kind === 'note' ? 'note' : 'audit_header',
    source_id: id,
    summary,
    detail: {},
    actor: null,
    actor_kind: 'person',
    run_id: null,
    source_record: { entity: 'contact', id: 'c1' },
  } as TimelineEntry;
}

/** An entry at `at`, of `kind`. */
function at(id: string, kind: TimelineEntry['kind'], when: string, pinned = false): TimelineEntry {
  return { ...entry(id, kind, id), occurred_at: when, pinned } as TimelineEntry;
}

describe('RecordTimelinePanelComponent', () => {
  let timeline: ReturnType<typeof vi.fn>;
  let summary: ReturnType<typeof vi.fn>;
  let pinned: ReturnType<typeof vi.fn>;
  let pin: ReturnType<typeof vi.fn>;
  let unpin: ReturnType<typeof vi.fn>;
  let addNote: ReturnType<typeof vi.fn>;
  let logActivity: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    timeline = vi.fn();
    summary = vi.fn().mockReturnValue(of(null));
    pinned = vi.fn().mockReturnValue(of({ items: [] }));
    pin = vi.fn().mockReturnValue(of(undefined));
    unpin = vi.fn().mockReturnValue(of(undefined));
    addNote = vi.fn().mockReturnValue(of({}));
    logActivity = vi.fn().mockReturnValue(of({}));
    TestBed.configureTestingModule({
      imports: [RecordTimelinePanelComponent],
      providers: [
        { provide: RecordTimelineService, useValue: { timeline, summary, pinned, pin, unpin, addNote, logActivity } },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => null, calendar: () => null, digits: () => null } },
      ],
    });
  });

  function mount() {
    const fixture = TestBed.createComponent(RecordTimelinePanelComponent);
    fixture.componentRef.setInput('entityName', 'contact');
    fixture.componentRef.setInput('recordId', 'rec-1');
    fixture.detectChanges();
    return fixture;
  }

  it('loads the first page for the record and renders each entry', () => {
    timeline.mockReturnValue(of({ items: [entry('a', 'audit_event', 'updated by Ann'), entry('b', 'note', 'Note: hi')] }));
    const fixture = mount();
    expect(timeline).toHaveBeenCalledWith('contact', 'rec-1', { cursor: null, pageSize: TIMELINE_PAGE_SIZE, kinds: [] });
    const el: HTMLElement = fixture.nativeElement;
    const items = el.querySelectorAll('[data-testid="timeline-entry"]');
    expect(items.length).toBe(2);
    expect(items[1].textContent).toContain('Note: hi');
    expect(el.querySelector('[data-testid="timeline-load-more"]')).toBeNull();
  });

  it('appends the next page with the returned cursor on "load more"', () => {
    timeline.mockReturnValueOnce(of({ items: [entry('a', 'note', 'first')], next_cursor: 'CUR' }));
    timeline.mockReturnValueOnce(of({ items: [entry('b', 'note', 'second')] }));
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    el.querySelector<HTMLButtonElement>('[data-testid="timeline-load-more"]')!.click();
    fixture.detectChanges();
    expect(timeline).toHaveBeenLastCalledWith('contact', 'rec-1', { cursor: 'CUR', pageSize: TIMELINE_PAGE_SIZE, kinds: [] });
    expect(el.querySelectorAll('[data-testid="timeline-entry"]').length).toBe(2);
    expect(el.querySelector('[data-testid="timeline-load-more"]')).toBeNull();
  });

  it('refetches from the first page, filtered, when a kind chip is toggled', () => {
    timeline.mockReturnValueOnce(of({ items: [entry('a', 'note', 'first')], next_cursor: 'CUR' }));
    timeline.mockReturnValueOnce(of({ items: [entry('c', 'note', 'only notes')] }));
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    el.querySelector<HTMLButtonElement>('[data-testid="timeline-chip-note"]')!.click();
    fixture.detectChanges();
    expect(timeline).toHaveBeenLastCalledWith('contact', 'rec-1', { cursor: null, pageSize: TIMELINE_PAGE_SIZE, kinds: ['note'] });
    const items = el.querySelectorAll('[data-testid="timeline-entry"]');
    expect(items.length).toBe(1);
    expect(items[0].textContent).toContain('only notes');
    expect(el.querySelector('[data-testid="timeline-chip-note"]')!.getAttribute('aria-pressed')).toBe('true');
  });

  it('shows an error and no entries when the request fails', () => {
    timeline.mockReturnValue(throwError(() => new Error('boom')));
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[role="alert"]')?.textContent).toContain('recordTimeline.error');
    expect(el.querySelector('[data-testid="timeline-empty"]')).toBeNull();
  });

  it('says so when the record has no entries', () => {
    timeline.mockReturnValue(of({ items: [] }));
    const fixture = mount();
    expect(fixture.nativeElement.querySelector('[data-testid="timeline-empty"]')).not.toBeNull();
  });

  it('shows the summary on open with its cited events, and a citation marks its entry', () => {
    timeline.mockReturnValue(of({ items: [entry('a', 'note', 'Note: discount approved'), entry('b', 'note', 'Note: hi')] }));
    summary.mockReturnValue(of({
      answer: 'The discount was approved.',
      citations: [{ evidence: 'E1', kind: 'note', source_id: 'a', occurred_at: '2026-09-23T10:00:00Z' }],
    }));
    const fixture = mount();
    expect(summary).toHaveBeenCalledWith('contact', 'rec-1');
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="timeline-summary"]')?.textContent).toContain('The discount was approved.');
    el.querySelector<HTMLButtonElement>('[data-testid="timeline-cite-a"]')!.click();
    fixture.detectChanges();
    expect(el.querySelector('#tl-a')?.classList.contains('rt-item-cited')).toBe(true);
    expect(el.querySelector('#tl-b')?.classList.contains('rt-item-cited')).toBe(false);
  });

  it('shows no summary when there is none or AI is unavailable', () => {
    timeline.mockReturnValue(of({ items: [entry('a', 'note', 'Note: hi')] }));
    summary.mockReturnValue(throwError(() => new Error('ai off')));
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelector('[data-testid="timeline-summary"]')).toBeNull();
    expect(el.querySelector('[data-testid="timeline-summary-loading"]')).toBeNull();
    expect(el.querySelector('[role="alert"]')).toBeNull();
  });

  it('reads the summary only from a completed outcome with an answer', () => {
    expect(timelineSummary({ status: 'completed', result: { answer: 'x', citations: [] } }))
      .toEqual({ answer: 'x', citations: [] });
    expect(timelineSummary({ status: 'completed', result: { answer: null } })).toBeNull();
    expect(timelineSummary({ status: 'pending_confirmation' })).toBeNull();
    expect(timelineSummary(null)).toBeNull();
  });

  it('shows the pinned entries on top and pins an entry from the list', () => {
    timeline.mockReturnValue(of({ items: [at('a', 'note', '2026-09-23T10:00:00Z')] }));
    pinned.mockReturnValueOnce(of({ items: [at('p', 'note', '2026-09-01T10:00:00Z', true)] }));
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    expect(pinned).toHaveBeenCalledWith('contact', 'rec-1');
    expect(el.querySelectorAll('[data-testid="timeline-pinned-entry"]').length).toBe(1);
    const button = el.querySelector<HTMLButtonElement>('[data-testid="timeline-pin-a"]')!;
    expect(button.getAttribute('aria-pressed')).toBe('false');
    button.click();
    fixture.detectChanges();
    expect(pin).toHaveBeenCalledWith('contact', 'rec-1', expect.objectContaining({ source_id: 'a' }));
    expect(el.querySelector('[data-testid="timeline-pin-a"]')!.getAttribute('aria-pressed')).toBe('true');
    expect(pinned).toHaveBeenCalledTimes(2);
  });

  it('marks a long gap between contacts', () => {
    timeline.mockReturnValue(of({ items: [
      at('c2', 'communication', '2026-09-30T10:00:00Z'),
      at('n1', 'note', '2026-09-20T10:00:00Z'),
      at('c1', 'communication', '2026-09-01T10:00:00Z'),
    ] }));
    const fixture = mount();
    const gaps = fixture.nativeElement.querySelectorAll('[data-testid="timeline-gap"]');
    expect(gaps.length).toBe(1);
    const gap = contactGaps([
      at('c2', 'communication', '2026-09-30T10:00:00Z'),
      at('c1', 'communication', '2026-09-01T10:00:00Z'),
    ], 14);
    expect([...gap.entries()]).toEqual([[1, 29]]);
    expect(contactGaps([at('c1', 'communication', '2026-09-01T10:00:00Z')], 14).size).toBe(0);
    expect(contactGaps([
      at('c2', 'communication', '2026-09-05T10:00:00Z'),
      at('c1', 'communication', '2026-09-01T10:00:00Z'),
    ], 14).size).toBe(0);
  });

  it('adds a note inline and shows the timeline again', () => {
    timeline.mockReturnValue(of({ items: [] }));
    const fixture = mount();
    const el: HTMLElement = fixture.nativeElement;
    el.querySelector<HTMLButtonElement>('[data-testid="timeline-add-note"]')!.click();
    fixture.detectChanges();
    fixture.componentInstance.formText.set('Called back, wants a quote');
    fixture.detectChanges();
    fixture.componentInstance.saveForm();
    fixture.detectChanges();
    expect(addNote).toHaveBeenCalledWith('contact', 'rec-1', 'Called back, wants a quote');
    expect(el.querySelector('[data-testid="timeline-form"]')).toBeNull();
    expect(timeline).toHaveBeenCalledTimes(2);
    fixture.componentInstance.openForm('task');
    fixture.componentInstance.formText.set('Send the quote');
    fixture.componentInstance.formDue.set('2026-10-30');
    fixture.componentInstance.saveForm();
    expect(logActivity).toHaveBeenCalledWith('contact', 'rec-1', { type: 'task', subject: 'Send the quote', due: '2026-10-30' });
  });

  it('counts live changes to the record and reloads on "new"', () => {
    timeline.mockReturnValue(of({ items: [] }));
    const fixture = mount();
    const live = TestBed.inject(LiveChannel);
    live.records.next({ changes: [
      { entity: 'contact', id: 'rec-1', op: 'update' },
      { entity: 'contact', id: 'other', op: 'update' },
      { entity: 'note', id: 'n9', op: 'create' },
    ] });
    fixture.detectChanges();
    expect(fixture.componentInstance.fresh()).toBe(2);
    const el: HTMLElement = fixture.nativeElement;
    el.querySelector<HTMLButtonElement>('[data-testid="timeline-fresh"]')!.click();
    fixture.detectChanges();
    expect(fixture.componentInstance.fresh()).toBe(0);
    expect(el.querySelector('[data-testid="timeline-fresh"]')).toBeNull();
    expect(timeline).toHaveBeenCalledTimes(2);
  });

  it('offers Reply on a communication', () => {
    timeline.mockReturnValue(of({ items: [at('c1', 'communication', '2026-09-01T10:00:00Z'), at('n1', 'note', '2026-09-01T09:00:00Z')] }));
    const fixture = mount();
    const replies: TimelineEntry[] = [];
    fixture.componentInstance.reply.subscribe(e => replies.push(e));
    const el: HTMLElement = fixture.nativeElement;
    const buttons = el.querySelectorAll<HTMLButtonElement>('[data-testid="timeline-reply"]');
    expect(buttons.length).toBe(1);
    buttons[0].click();
    expect(replies.map(r => r.source_id)).toEqual(['c1']);
  });
});
