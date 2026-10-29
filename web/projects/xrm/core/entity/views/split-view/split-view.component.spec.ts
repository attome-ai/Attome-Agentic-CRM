import { TestBed } from '@angular/core/testing';
import { LangService } from '@attome/base';
import { QueryService } from '@attome/xrm/core/query/data';
import { of } from 'rxjs';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SplitViewComponent, displayValue, nextIndex } from './split-view.component';

describe('split view helpers (A13-T3)', () => {
  it('moves with the arrow keys inside the list', () => {
    expect(nextIndex(0, 'ArrowDown', 3)).toBe(1);
    expect(nextIndex(2, 'ArrowDown', 3)).toBe(2);
    expect(nextIndex(0, 'ArrowUp', 3)).toBe(0);
    expect(nextIndex(1, 'End', 3)).toBe(2);
    expect(nextIndex(2, 'Home', 3)).toBe(0);
    expect(nextIndex(1, 'a', 3)).toBe(1);
    expect(nextIndex(0, 'ArrowDown', 0)).toBe(-1);
  });

  it('shows a value as text', () => {
    expect(displayValue(null)).toBe('—');
    expect(displayValue(['a', 'b'])).toBe('a, b');
    expect(displayValue(12)).toBe('12');
  });
});

describe('SplitViewComponent (A13-T3)', () => {
  let execute: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    execute = vi.fn(() => of({ data: {
      columns: [
        { name: 'id', display_name: 'Id', is_visible: false },
        { name: 'name', display_name: 'Name', is_visible: true },
        { name: 'account_ref.name', display_name: 'Account', is_visible: true },
      ],
      records: [
        { id: 'r1', name: 'Alpha', 'account_ref.name': 'Acme' },
        { id: 'r2', name: 'Beta', 'account_ref.name': null },
        { id: 'r3', name: 'Gamma', 'account_ref.name': 'Globex' },
      ],
    } }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [SplitViewComponent],
      providers: [
        { provide: QueryService, useValue: { execute } },
        { provide: LangService, useValue: { translate: (k: string) => k, isRtl: () => false } },
      ],
    });
  });

  function render(viewId: string | null = null) {
    const fixture = TestBed.createComponent(SplitViewComponent);
    fixture.componentRef.setInput('entityName', 'opportunity');
    fixture.componentRef.setInput('viewId', viewId);
    fixture.detectChanges();
    TestBed.flushEffects();
    fixture.detectChanges();
    return fixture;
  }

  const record = (root: HTMLElement) => root.querySelector('[data-testid="split-record"]') as HTMLElement;

  it('lists the records and shows the first one, related columns included', () => {
    const root: HTMLElement = render().nativeElement;
    expect(execute).toHaveBeenCalledWith(expect.objectContaining({ entity: 'opportunity', page: 1 }));
    expect(root.querySelectorAll('[role="option"]').length).toBe(3);
    expect(record(root).textContent).toContain('Alpha');
    expect(record(root).textContent).toContain('Acme');
  });

  it('reads the chosen view when one is given', () => {
    render('view-1');
    expect(execute).toHaveBeenCalledWith(expect.objectContaining({ view_id: 'view-1' }));
  });

  it('moves through the records with the keyboard and opens with Enter', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    const opened = vi.fn();
    fixture.componentInstance.openRecord.subscribe(opened);
    const list = root.querySelector('[data-testid="split-list"]') as HTMLElement;
    list.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true }));
    fixture.detectChanges();
    expect(record(root).textContent).toContain('Beta');
    expect(list.getAttribute('aria-activedescendant')).toBe('sv-r2');
    list.dispatchEvent(new KeyboardEvent('keydown', { key: 'End', bubbles: true }));
    fixture.detectChanges();
    expect(record(root).textContent).toContain('Gamma');
    list.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    expect(opened).toHaveBeenCalledWith('r3');
  });

  it('opens a record from its button and selects one by click', () => {
    const fixture = render();
    const root: HTMLElement = fixture.nativeElement;
    const opened = vi.fn();
    fixture.componentInstance.openRecord.subscribe(opened);
    (root.querySelectorAll('[role="option"]')[2] as HTMLElement).click();
    fixture.detectChanges();
    (root.querySelector('[data-testid="split-open"]') as HTMLButtonElement).click();
    expect(opened).toHaveBeenCalledWith('r3');
  });
});
