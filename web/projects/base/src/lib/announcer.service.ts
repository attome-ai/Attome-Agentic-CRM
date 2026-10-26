import { DOCUMENT } from '@angular/common';
import { DestroyRef, inject, Injectable } from '@angular/core';

/** How urgently a screen reader reads a message: `assertive` interrupts. */
export type Politeness = 'polite' | 'assertive';

/**
 * How long a region stays empty before the message goes in. A screen reader
 * reads a live region when its text changes, so the same message twice in a
 * row ("Saved.", "Saved.") is only heard twice if the region is cleared
 * first and filled a moment later.
 */
export const ANNOUNCE_DELAY_MS = 100;

/** The attribute that marks the announcer's own regions. */
export const ANNOUNCER_ATTR = 'data-attome-announcer';

/**
 * B22-T3 — the one live-region announcer. A screen reader does not read text
 * that appears somewhere on the page (a "Saved" tick, an error under the
 * button, a "3 new rows" bar inserted by `@if`) unless it lands in a live
 * region that already existed. This service keeps two such regions, one
 * polite and one assertive, visually hidden at the end of `<body>`, and puts
 * each message into the right one.
 *
 * Saves are polite; errors are assertive. The caller passes text already in
 * the person's language.
 */
@Injectable({ providedIn: 'root' })
export class Announcer {
  private readonly doc = inject(DOCUMENT);
  private readonly regions = new Map<Politeness, HTMLElement>();
  private readonly timers = new Map<Politeness, ReturnType<typeof setTimeout>>();

  constructor() {
    inject(DestroyRef).onDestroy(() => {
      for (const timer of this.timers.values()) clearTimeout(timer);
      for (const region of this.regions.values()) region.remove();
      this.timers.clear();
      this.regions.clear();
    });
  }

  /** Reads `message` out; blank text is ignored. */
  announce(message: string, politeness: Politeness = 'polite'): void {
    const text = message.trim();
    if (!text) return;
    const region = this.region(politeness);
    if (!region) return;
    region.textContent = '';
    const pending = this.timers.get(politeness);
    if (pending !== undefined) clearTimeout(pending);
    this.timers.set(politeness, setTimeout(() => {
      this.timers.delete(politeness);
      region.textContent = text;
    }, ANNOUNCE_DELAY_MS));
  }

  /** Empties both regions, dropping a message not yet read. */
  clear(): void {
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
    for (const region of this.regions.values()) region.textContent = '';
  }

  private region(politeness: Politeness): HTMLElement | null {
    const existing = this.regions.get(politeness);
    if (existing?.isConnected) return existing;
    const body = this.doc.body;
    if (!body) return null;
    const region = this.doc.createElement('div');
    region.setAttribute(ANNOUNCER_ATTR, politeness);
    region.setAttribute('aria-live', politeness);
    region.setAttribute('aria-atomic', 'true');
    region.setAttribute('role', politeness === 'assertive' ? 'alert' : 'status');
    // Visually hidden, still in the accessibility tree.
    Object.assign(region.style, {
      position: 'absolute',
      width: '1px',
      height: '1px',
      margin: '-1px',
      padding: '0',
      overflow: 'hidden',
      clipPath: 'inset(50%)',
      whiteSpace: 'nowrap',
      border: '0',
    });
    body.appendChild(region);
    this.regions.set(politeness, region);
    return region;
  }
}
