import { Injectable, inject } from '@angular/core';
import { ATTOME_CONFIG } from '@attome/base';

/** The two vitals reported: largest contentful paint and interaction to next paint. */
export type VitalName = 'LCP' | 'INP';

/** One `event` timing entry, as much of it as INP needs. */
interface InteractionTiming {
  duration: number;
  interactionId?: number;
}

/**
 * AA12-T1: measures how fast the app feels in this browser and reports it to
 * the metrics store (`POST /api/v1/telemetry/web-vitals`): the largest
 * contentful paint of the page load, and the slowest interaction (INP). Both
 * are sent when the page is hidden, the moment the Web Vitals method
 * prescribes, with `keepalive` so the request outlives the tab. A browser
 * without `PerformanceObserver` reports nothing.
 */
@Injectable({ providedIn: 'root' })
export class WebVitals {
  private readonly config = inject(ATTOME_CONFIG, { optional: true });
  private started = false;
  private lcp = 0;
  private inp = 0;
  private lcpSent = false;

  /** Starts measuring (once). */
  start(): void {
    if (this.started || typeof PerformanceObserver === 'undefined' || typeof document === 'undefined') return;
    this.started = true;
    this.observe('largest-contentful-paint', entries => {
      const last = entries[entries.length - 1];
      if (last) this.lcp = last.startTime;
    });
    this.observe('event', entries => this.recordInteractions(entries as unknown as InteractionTiming[]), {
      durationThreshold: 40,
    });
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'hidden') this.flush();
    });
  }

  /** Keeps the slowest interaction seen; entries without an interaction id are not interactions. */
  recordInteractions(entries: readonly InteractionTiming[]): void {
    for (const entry of entries) {
      if ((entry.interactionId ?? 0) > 0 && entry.duration > this.inp) this.inp = entry.duration;
    }
  }

  /** Records the page's largest contentful paint. */
  recordLcp(startTime: number): void {
    this.lcp = startTime;
  }

  /** Sends what was measured: LCP once per page, INP whenever a slower one was seen. */
  flush(path = typeof location === 'undefined' ? '/' : location.pathname): void {
    const area = vitalArea(path);
    if (this.lcp > 0 && !this.lcpSent) {
      this.lcpSent = true;
      this.send('LCP', this.lcp, area);
    }
    if (this.inp > 0) {
      this.send('INP', this.inp, area);
      this.inp = 0;
    }
  }

  private send(name: VitalName, value: number, area: string): void {
    if (typeof fetch === 'undefined') return;
    void fetch(`${this.config?.apiUrl ?? ''}/api/v1/telemetry/web-vitals`, {
      method: 'POST',
      keepalive: true,
      credentials: 'include',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name, value: Math.round(value), area }),
    }).catch(() => undefined);
  }

  private observe(
    type: string,
    handle: (entries: PerformanceEntry[]) => void,
    extra: Record<string, unknown> = {},
  ): void {
    try {
      new PerformanceObserver(list => handle(list.getEntries())).observe({ type, buffered: true, ...extra });
    } catch {
      // This browser does not report this entry type.
    }
  }
}

/** The screen area a path belongs to: its module under `/xrm/`, else its first segment. */
export function vitalArea(path: string): string {
  const parts = path.split('/').filter(Boolean).map(p => p.toLowerCase());
  const area = parts[0] === 'xrm' ? parts[1] ?? 'xrm' : parts[0] ?? 'home';
  return /^[a-z-]{1,24}$/.test(area) ? area : 'other';
}
