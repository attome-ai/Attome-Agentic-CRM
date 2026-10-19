import { Injectable, computed, inject, signal } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { ApiService } from '../api.service';
import { TOURS_SEEN_SETTING, Tour, autoTour, tourFor } from './tour';

/** The running tour and the step on show. */
export interface ActiveTour {
  tour: Tour;
  step: number;
}

/**
 * B14-T1: loads the tours this person may see and the ones they already
 * finished, starts a tour by itself once on its route, and replays one on
 * request. Finishing or skipping a tour records it in `core.tours_seen`; a
 * replay changes nothing. A failure to load leaves tours off; it never
 * blocks the page.
 */
@Injectable({ providedIn: 'root' })
export class TourService {
  private readonly api = inject(ApiService);

  readonly tours = signal<Tour[]>([]);
  readonly seen = signal<string[]>([]);
  readonly active = signal<ActiveTour | null>(null);
  readonly step = computed(() => {
    const active = this.active();
    return active ? active.tour.steps[active.step] ?? null : null;
  });
  private loading: Promise<void> | null = null;
  private replaying = false;

  /** Loads once; later calls wait for the same load. */
  load(): Promise<void> {
    this.loading ??= Promise.all([
      firstValueFrom(this.api.get<{ items: Tour[] }>('/api/v1/model/tours')),
      firstValueFrom(this.api.get<{ items: { key: string; value: unknown }[] }>('/api/v1/settings/me')),
    ]).then(
      ([tours, settings]) => {
        this.tours.set(tours.items ?? []);
        const seen = settings.items?.find(s => s.key === TOURS_SEEN_SETTING)?.value;
        this.seen.set(Array.isArray(seen) ? seen.filter((s): s is string => typeof s === 'string') : []);
      },
      () => undefined,
    );
    return this.loading;
  }

  /** After a navigation: starts the route's tour if it starts by itself and is new. */
  async onNavigate(url: string): Promise<void> {
    await this.load();
    if (this.active()) return;
    const tour = autoTour(this.tours(), url, this.seen());
    if (tour) this.start(tour, false);
  }

  /** Whether `url` has a tour to replay. */
  hasTour(url: string): boolean {
    return tourFor(this.tours(), url) !== null;
  }

  /** Replays the tour of `url`; false when it has none. */
  async replayFor(url: string): Promise<boolean> {
    await this.load();
    const tour = tourFor(this.tours(), url);
    if (!tour) return false;
    this.start(tour, true);
    return true;
  }

  start(tour: Tour, replay: boolean): void {
    this.replaying = replay;
    this.active.set({ tour, step: 0 });
  }

  next(): void {
    const active = this.active();
    if (!active) return;
    if (active.step + 1 >= active.tour.steps.length) {
      this.finish();
      return;
    }
    this.active.set({ ...active, step: active.step + 1 });
  }

  back(): void {
    const active = this.active();
    if (active && active.step > 0) this.active.set({ ...active, step: active.step - 1 });
  }

  /** Ends the tour (finished or skipped) and remembers it, unless replayed. */
  finish(): void {
    const active = this.active();
    this.active.set(null);
    if (!active || this.replaying || this.seen().includes(active.tour.id)) return;
    const seen = [...this.seen(), active.tour.id].slice(-500);
    this.seen.set(seen);
    this.api.put(`/api/v1/settings/me/${TOURS_SEEN_SETTING}`, { value: seen }).subscribe({ error: () => undefined });
  }
}
