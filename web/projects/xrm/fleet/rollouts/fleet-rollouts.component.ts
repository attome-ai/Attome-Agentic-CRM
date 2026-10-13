import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { RouterLink } from '@angular/router';
import { LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fleetErrorText } from '../data/fleet-error-text';
import { fleetLabel, type FleetLabelSet } from '../data/fleet-labels';
import type { RolloutView } from '../data/fleet.types';

/** `fleet-pill--ok|warn|bad` for a rollout status. */
export function rolloutTone(status: string): string {
  switch (status) {
    case 'completed':   return 'fleet-pill--ok';
    case 'halted':
    case 'cancelled':   return 'fleet-pill--bad';
    default:            return 'fleet-pill--warn';
  }
}

/**
 * `/xrm/fleet/rollouts` (D-792 F4): every rollout, newest first, with its
 * status and current wave. One-based paging.
 */
@Component({
  selector: 'attome-fleet-rollouts',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', '../fleet.css', './fleet-rollouts.component.css'],
  templateUrl: './fleet-rollouts.component.html',
})
export class FleetRolloutsComponent implements OnInit {
  private readonly svc = inject(FleetService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly pageSize = 25;

  readonly rollouts = signal<RolloutView[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));

  ngOnInit(): void {
    this.load();
  }

  text(set: FleetLabelSet, value: string | null | undefined): string {
    return fleetLabel(this.lang, set, value);
  }

  tone(status: string): string {
    return rolloutTone(status);
  }

  /** "Wave 2 of 3: early", or nothing when the rollout has no waves. */
  waveText(r: RolloutView): string {
    if (r.waves.length === 0) return '';
    const index = Math.min(r.cursor, r.waves.length - 1);
    return this.lang.translate('fleet.rollouts.waveOf', {
      wave: index + 1,
      waves: r.waves.length,
      name: fleetLabel(this.lang, 'ring', r.waves[index].name),
    });
  }

  previous(): void {
    if (this.page() <= 1 || this.loading()) return;
    this.page.update(p => p - 1);
    this.load();
  }

  next(): void {
    if (this.page() >= this.pages() || this.loading()) return;
    this.page.update(p => p + 1);
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listRollouts(this.page(), this.pageSize).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.rollouts.set(res.items);
        this.total.set(res.total);
        this.loading.set(false);
      },
      error: (err: ApiError) => {
        this.error.set(fleetErrorText(this.lang, err));
        this.loading.set(false);
      },
    });
  }
}
