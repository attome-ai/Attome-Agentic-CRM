import { TestBed } from '@angular/core/testing';
import { of, throwError } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService, UserPreferencesService } from '@attome/base';
import { RecordTimelinePanelComponent, TIMELINE_PAGE_SIZE } from './record-timeline-panel.component';
import { RecordTimelineService, TimelineEntry } from './record-timeline.service';

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

describe('RecordTimelinePanelComponent', () => {
  let timeline: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    timeline = vi.fn();
    TestBed.configureTestingModule({
      imports: [RecordTimelinePanelComponent],
      providers: [
        { provide: RecordTimelineService, useValue: { timeline } },
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
});
