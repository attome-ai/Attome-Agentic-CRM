import { describe, expect, it } from 'vitest';
import { focusableElements, trapFocus } from './focus-trap';

/** NGB-3.1 — the focus trap the dialog host and the step-up prompt both use. */
describe('focus-trap', () => {
  function build(): { root: HTMLElement; outside: HTMLButtonElement; first: HTMLButtonElement; last: HTMLButtonElement } {
    document.body.innerHTML = `
      <button id="trigger">trigger</button>
      <div id="root">
        <button id="first">first</button>
        <input id="middle" />
        <button id="last">last</button>
        <button id="disabled" disabled>disabled</button>
      </div>
    `;
    return {
      root: document.getElementById('root') as HTMLElement,
      outside: document.getElementById('trigger') as HTMLButtonElement,
      first: document.getElementById('first') as HTMLButtonElement,
      last: document.getElementById('last') as HTMLButtonElement,
    };
  }

  function tab(shiftKey = false): KeyboardEvent {
    const event = new KeyboardEvent('keydown', { key: 'Tab', shiftKey, bubbles: true, cancelable: true });
    document.activeElement?.dispatchEvent(event);
    return event;
  }

  it('lists the enabled focusable descendants only', () => {
    const { root } = build();
    expect(focusableElements(root).map(el => el.id)).toEqual(['first', 'middle', 'last']);
  });

  it('wraps Tab from the last element to the first', () => {
    const { root, last, first } = build();
    trapFocus(root);
    last.focus();
    expect(tab().defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(first);
  });

  it('wraps Shift+Tab from the first element to the last', () => {
    const { root, first, last } = build();
    trapFocus(root);
    first.focus();
    expect(tab(true).defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(last);
  });

  // Deliberate limitation, documented rather than "fixed": the listener sits
  // on the modal card, so a keydown that happens on an element outside it never
  // bubbles through the trap. Every modal host moves focus inside on open
  // (NGB-3.1), which is what keeps this from mattering.
  it('does not intercept a Tab that never passes through the modal', () => {
    const { root, outside } = build();
    trapFocus(root);
    outside.focus();
    expect(tab().defaultPrevented).toBe(false);
    expect(document.activeElement).toBe(outside);
  });

  it('leaves a Tab in the middle of the modal to the browser', () => {
    const { root } = build();
    trapFocus(root);
    (document.getElementById('middle') as HTMLInputElement).focus();
    expect(tab().defaultPrevented).toBe(false);
  });

  it('restores focus to the trigger on teardown', () => {
    const { root, outside } = build();
    outside.focus();
    const release = trapFocus(root);
    (document.getElementById('first') as HTMLButtonElement).focus();
    release();
    expect(document.activeElement).toBe(outside);
  });

  it('stops trapping after teardown', () => {
    const { root, outside } = build();
    const release = trapFocus(root);
    release();
    outside.focus();
    expect(tab().defaultPrevented).toBe(false);
  });
});
