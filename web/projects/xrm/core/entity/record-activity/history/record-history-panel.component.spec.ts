import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService, UserPreferencesService } from '@attome/base';
import { RecordHistoryPanelComponent, historyValue } from './record-history-panel.component';
import { RecordHistoryField, RecordTimelineService } from '../timeline/record-timeline.service';

function field(overrides: Partial<RecordHistoryField>): RecordHistoryField {
  return {
    field_name: 'name',
    display_name: null,
    field_type: 'text',
    old_value: null,
    new_value: null,
    old_display_value: null,
    new_display_value: null,
    old_lookup_name: null,
    new_lookup_name: null,
    masked: false,
    ...overrides,
  };
}

const echo = (k: string) => k;

describe('historyValue', () => {
  it('renders an empty side as null', () => {
    expect(historyValue(field({ old_value: null }), 'old', echo)).toEqual({ text: null, isDate: false });
  });

  it('prefers a lookup name over the raw id', () => {
    const f = field({ field_type: 'lookup', new_value: '0196-uuid', new_lookup_name: 'Acme' });
    expect(historyValue(f, 'new', echo).text).toBe('Acme');
  });

  it('reads a boolean as yes/no', () => {
    expect(historyValue(field({ field_type: 'bool', new_value: 'true' }), 'new', echo).text).toBe('recordHistory.yes');
    expect(historyValue(field({ field_type: 'bool', old_value: 'false' }), 'old', echo).text).toBe('recordHistory.no');
  });

  it('flags a parseable date for date formatting', () => {
    expect(historyValue(field({ field_type: 'date', new_value: '2026-09-23T10:00:00Z' }), 'new', echo).isDate).toBe(true);
    expect(historyValue(field({ field_type: 'date', new_value: 'garbage' }), 'new', echo).isDate).toBe(false);
  });

  it('prefers the display value for other types', () => {
    expect(historyValue(field({ new_value: 'open', new_display_value: 'Open' }), 'new', echo).text).toBe('Open');
  });
});

describe('RecordHistoryPanelComponent', () => {
  let history: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    history = vi.fn();
    TestBed.configureTestingModule({
      imports: [RecordHistoryPanelComponent],
      providers: [
        { provide: RecordTimelineService, useValue: { history } },
        { provide: LangService, useValue: { translate: (k: string) => k, intlLocale: () => 'en-US' } },
        { provide: UserPreferencesService, useValue: { timezone: () => null, calendar: () => null, digits: () => null } },
      ],
    });
  });

  function mount() {
    const fixture = TestBed.createComponent(RecordHistoryPanelComponent);
    fixture.componentRef.setInput('entityName', 'contact');
    fixture.componentRef.setInput('recordId', 'rec-1');
    fixture.detectChanges();
    return fixture;
  }

  it('groups fields per change and renders old → new, with sensitive fields masked', () => {
    history.mockReturnValue(of({
      items: [{
        audit_id: 'h1',
        changed_on: '2026-09-23T10:00:00Z',
        operation: 'updated',
        user_id: null,
        user_display_name: 'Ann',
        fields: [
          field({ field_name: 'name', display_name: 'Name', old_value: 'Old', new_value: 'New' }),
          field({ field_name: 'salary', masked: true }),
        ],
      }],
      next_cursor: 'CUR',
    }));
    const fixture = mount();
    expect(history).toHaveBeenCalledWith('contact', 'rec-1', null);
    const el: HTMLElement = fixture.nativeElement;
    expect(el.querySelectorAll('[data-testid="history-change"]').length).toBe(1);
    const name = el.querySelector('[data-field="name"]')!;
    expect(name.textContent).toContain('Name');
    expect(name.textContent).toContain('Old');
    expect(name.textContent).toContain('New');
    const salary = el.querySelector('[data-field="salary"]')!;
    expect(salary.querySelector('[data-testid="history-masked"]')).not.toBeNull();
    expect(el.querySelector('[data-testid="history-load-more"]')).not.toBeNull();
  });

  it('asks for the next page with the returned cursor', () => {
    history.mockReturnValueOnce(of({ items: [], next_cursor: 'CUR' }));
    history.mockReturnValueOnce(of({ items: [] }));
    const fixture = mount();
    fixture.nativeElement.querySelector('[data-testid="history-load-more"]').click();
    fixture.detectChanges();
    expect(history).toHaveBeenLastCalledWith('contact', 'rec-1', 'CUR');
    expect(fixture.nativeElement.querySelector('[data-testid="history-load-more"]')).toBeNull();
  });
});
