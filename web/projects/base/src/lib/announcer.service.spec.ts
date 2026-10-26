import { TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ANNOUNCE_DELAY_MS, ANNOUNCER_ATTR, Announcer } from './announcer.service';

/** B22-T3 — saves and errors reach a screen reader through a live region. */
describe('Announcer', () => {
  function setUp(): Announcer {
    TestBed.configureTestingModule({});
    return TestBed.inject(Announcer);
  }

  function region(politeness: 'polite' | 'assertive'): HTMLElement | null {
    return document.querySelector(`[${ANNOUNCER_ATTR}="${politeness}"]`);
  }

  beforeEach(() => vi.useFakeTimers());
  afterEach(() => {
    TestBed.resetTestingModule();
    vi.useRealTimers();
  });

  it('puts a save into a polite status region', () => {
    const announcer = setUp();
    announcer.announce('Saved.');
    const polite = region('polite');
    expect(polite?.getAttribute('aria-live')).toBe('polite');
    expect(polite?.getAttribute('role')).toBe('status');
    expect(polite?.getAttribute('aria-atomic')).toBe('true');
    expect(polite?.textContent).toBe('');
    vi.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    expect(polite?.textContent).toBe('Saved.');
  });

  it('puts an error into an assertive alert region', () => {
    const announcer = setUp();
    announcer.announce('You do not have permission to do that.', 'assertive');
    vi.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    const assertive = region('assertive');
    expect(assertive?.getAttribute('role')).toBe('alert');
    expect(assertive?.getAttribute('aria-live')).toBe('assertive');
    expect(assertive?.textContent).toBe('You do not have permission to do that.');
    expect(region('polite')).toBeNull();
  });

  it('clears the region first, so the same message twice is heard twice', () => {
    const announcer = setUp();
    announcer.announce('Saved.');
    vi.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    announcer.announce('Saved.');
    expect(region('polite')?.textContent).toBe('');
    vi.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    expect(region('polite')?.textContent).toBe('Saved.');
  });

  it('keeps one region per politeness and the latest message', () => {
    const announcer = setUp();
    announcer.announce('First');
    announcer.announce('Second');
    vi.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    expect(document.querySelectorAll(`[${ANNOUNCER_ATTR}="polite"]`).length).toBe(1);
    expect(region('polite')?.textContent).toBe('Second');
  });

  it('ignores blank text and clear() drops a pending message', () => {
    const announcer = setUp();
    announcer.announce('   ');
    expect(region('polite')).toBeNull();
    announcer.announce('Pending');
    announcer.clear();
    vi.advanceTimersByTime(ANNOUNCE_DELAY_MS);
    expect(region('polite')?.textContent).toBe('');
  });

  it('removes its regions when the injector is destroyed', () => {
    setUp().announce('Saved.');
    expect(region('polite')).not.toBeNull();
    TestBed.resetTestingModule();
    expect(region('polite')).toBeNull();
  });
});
