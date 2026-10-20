import { Component } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { of } from 'rxjs';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { LangService } from '../lang.service';
import {
  MentionCandidate,
  MentionPickerComponent,
  MentionSearch,
  activeMention,
  mentionToken,
} from './mention-picker.component';

const ANA: MentionCandidate = { kind: 'user', id: 'u1', label: 'Ana', detail: 'ana@example.test' };
const OPS: MentionCandidate = { kind: 'team', id: 't1', label: 'Ops' };

@Component({
  standalone: true,
  imports: [MentionPickerComponent],
  template: `
    <textarea #box></textarea>
    <base-mention-picker [target]="box" [search]="search" (mentioned)="chosen.push($event)" />
  `,
})
class HostComponent {
  search: MentionSearch = vi.fn(() => of([ANA, OPS]));
  chosen: MentionCandidate[] = [];
}

describe('mention picker', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    TestBed.configureTestingModule({
      imports: [HostComponent],
      providers: [{ provide: LangService, useValue: { translate: (key: string) => key } }],
    });
  });

  afterEach(() => vi.useRealTimers());

  function render() {
    const fixture = TestBed.createComponent(HostComponent);
    fixture.detectChanges();
    const el: HTMLElement = fixture.nativeElement;
    const box = el.querySelector('textarea')!;
    const type = (value: string) => {
      box.value = value;
      box.setSelectionRange(value.length, value.length);
      box.dispatchEvent(new Event('input'));
      vi.advanceTimersByTime(200);
      fixture.detectChanges();
    };
    const key = (k: string) => {
      box.dispatchEvent(new KeyboardEvent('keydown', { key: k, cancelable: true }));
      fixture.detectChanges();
    };
    return { fixture, el, box, type, key };
  }

  it('finds the @query being typed, and only that', () => {
    expect(activeMention('hi @an', 6)).toEqual({ start: 3, query: 'an' });
    expect(activeMention('@', 1)).toEqual({ start: 0, query: '' });
    expect(activeMention('mail a@b', 8)).toBeNull();
    expect(activeMention('hi @an now', 10)).toBeNull();
    expect(activeMention('@[user:u1] ', 11)).toBeNull();
  });

  it('writes ids, never names', () => {
    expect(mentionToken(ANA)).toBe('@[user:u1]');
    expect(mentionToken(OPS)).toBe('@[team:t1]');
    expect(mentionToken({ kind: 'record', id: 'r1', label: 'Acme', entity: 'account' }))
      .toBe('@[record:account/r1]');
  });

  it('lists matches for the typed query and inserts the chosen one with Enter', () => {
    const { fixture, el, box, type, key } = render();
    type('Ask @an');
    const host = fixture.componentInstance;
    expect(host.search).toHaveBeenCalledWith('an');
    expect(el.querySelectorAll('[data-testid="mention-option"]').length).toBe(2);
    expect(box.getAttribute('aria-expanded')).toBe('true');
    key('Enter');
    expect(box.value).toBe('Ask @[user:u1] ');
    expect(host.chosen).toEqual([ANA]);
    expect(el.querySelector('[data-testid="mention-list"]')).toBeNull();
  });

  it('moves with the arrow keys and closes on Escape', () => {
    const { el, box, type, key } = render();
    type('@o');
    key('ArrowDown');
    const options = el.querySelectorAll('[data-testid="mention-option"]');
    expect(options[1].getAttribute('aria-selected')).toBe('true');
    expect(box.getAttribute('aria-activedescendant')).toContain('-1');
    key('Escape');
    expect(el.querySelector('[data-testid="mention-list"]')).toBeNull();
    expect(box.value).toBe('@o');
  });

  it('says when nothing matches', () => {
    const { fixture, el, type } = render();
    // Change what the bound search answers, not the function itself: a new
    // function on the plain host property is not seen by the OnPush picker.
    vi.mocked(fixture.componentInstance.search).mockImplementation(() => of([]));
    type('@zz');
    expect(el.querySelector('[data-testid="mention-none"]')?.textContent).toContain('mentionPicker.none');
  });
});
