import {
  ChangeDetectionStrategy, Component, DestroyRef, ElementRef, Injector, OnInit, afterNextRender, computed, inject,
  signal, viewChild,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fleetErrorText } from '../data/fleet-error-text';
import { fleetLabel, type FleetLabelSet } from '../data/fleet-labels';
import { FLEET_RINGS, type ChangesetFile, type DeploymentView } from '../data/fleet.types';

/** One wave of the preview: a ring and the customers in it. */
export interface PlannedWave {
  ring:        string;
  deployments: DeploymentView[];
}

/** The server's limits (`routes/rollouts.rs`). */
const MAX_TITLE = 200;
const MAX_CHANGESETS = 200;
const MAX_TARGETS = 100;

/**
 * Groups the chosen customers into waves the way the server does (by ring:
 * canary, then early, then broad); an empty ring is no wave.
 */
export function previewWaves(deployments: readonly DeploymentView[]): PlannedWave[] {
  return FLEET_RINGS
    .map(ring => ({ ring: ring as string, deployments: deployments.filter(d => d.ring === ring) }))
    .filter(w => w.deployments.length > 0);
}

/**
 * `/xrm/fleet/publish` (D-792 F4): pick changesets from the console's
 * `fleet.changesets_dir`, pick the customers, review the plan (order, waves
 * by ring, what each apply will need), then start the rollout (a fresh
 * step-up). Each customer then plans the changesets itself; applying and the
 * customer's own approval happen from the rollout page.
 */
@Component({
  selector: 'attome-fleet-publish',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', '../fleet.css', './fleet-publish.component.css'],
  templateUrl: './fleet-publish.component.html',
})
export class FleetPublishComponent implements OnInit {
  private readonly svc = inject(FleetService);
  private readonly lang = inject(LangService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);
  private readonly injector = inject(Injector);

  /** Focus targets when the page switches between choosing and reviewing. */
  private readonly reviewHeading = viewChild<ElementRef<HTMLElement>>('reviewHeading');
  private readonly reviewButton = viewChild<ElementRef<HTMLElement>>('reviewButton');

  readonly maxTitle = MAX_TITLE;

  readonly changesets = signal<ChangesetFile[]>([]);
  readonly changesetsLoading = signal(true);
  readonly changesetsError = signal<string | null>(null);
  readonly deployments = signal<DeploymentView[]>([]);
  readonly deploymentsLoading = signal(true);
  readonly deploymentsError = signal<string | null>(null);

  readonly title = signal('');
  readonly chosenChangesets = signal<ReadonlySet<string>>(new Set());
  readonly chosenDeployments = signal<ReadonlySet<string>>(new Set());

  readonly reviewing = signal(false);
  readonly starting = signal(false);
  readonly startError = signal<string | null>(null);

  /** The chosen changesets, in the order the server lists (and applies) them. */
  readonly selectedChangesets = computed(() =>
    this.changesets().filter(c => this.chosenChangesets().has(c.id)));
  readonly selectedDeployments = computed(() =>
    this.deployments().filter(d => this.chosenDeployments().has(d.id)));
  readonly waves = computed(() => previewWaves(this.selectedDeployments()));
  readonly prodTargets = computed(() => this.selectedDeployments().filter(d => d.environment === 'prod'));
  readonly windows = computed(() => this.selectedDeployments().filter(d => !!d.maintenance_window));

  readonly validationKey = computed<string | null>(() => {
    const title = this.title().trim();
    if (!title) return 'fleet.publish.needTitle';
    if (title.length > MAX_TITLE) return 'fleet.publish.titleTooLong';
    const changesets = this.selectedChangesets().length;
    if (changesets === 0) return 'fleet.publish.needChangeset';
    if (changesets > MAX_CHANGESETS) return 'fleet.publish.tooManyChangesets';
    const targets = this.selectedDeployments().length;
    if (targets === 0) return 'fleet.publish.needCustomer';
    if (targets > MAX_TARGETS) return 'fleet.publish.tooManyCustomers';
    return null;
  });

  ngOnInit(): void {
    this.svc.allChangesets().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: files => { this.changesets.set(files); this.changesetsLoading.set(false); },
      error: (err: ApiError) => {
        this.changesetsError.set(fleetErrorText(this.lang, err));
        this.changesetsLoading.set(false);
      },
    });
    this.svc.allDeployments(false).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: list => { this.deployments.set(list); this.deploymentsLoading.set(false); },
      error: (err: ApiError) => {
        this.deploymentsError.set(fleetErrorText(this.lang, err));
        this.deploymentsLoading.set(false);
      },
    });
  }

  text(set: FleetLabelSet, value: string | null | undefined): string {
    return fleetLabel(this.lang, set, value);
  }

  /** A customer the console can publish to: active, with a stored credential. */
  selectable(d: DeploymentView): boolean {
    return d.is_active && d.has_credential;
  }

  toggleChangeset(id: string, on: boolean): void {
    this.chosenChangesets.update(set => toggled(set, id, on));
    this.reviewing.set(false);
  }

  toggleDeployment(id: string, on: boolean): void {
    this.chosenDeployments.update(set => toggled(set, id, on));
    this.reviewing.set(false);
  }

  chooseAllChangesets(): void {
    this.chosenChangesets.set(new Set(this.changesets().filter(c => c.checksum_ok).map(c => c.id)));
    this.reviewing.set(false);
  }

  clearChangesets(): void {
    this.chosenChangesets.set(new Set());
    this.reviewing.set(false);
  }

  setTitle(value: string): void {
    this.title.set(value);
    this.reviewing.set(false);
  }

  review(): void {
    if (this.validationKey()) return;
    this.startError.set(null);
    this.reviewing.set(true);
    // The button that had focus is gone; move focus to the review heading.
    afterNextRender(() => this.reviewHeading()?.nativeElement.focus(), { injector: this.injector });
  }

  back(): void {
    this.reviewing.set(false);
    afterNextRender(() => this.reviewButton()?.nativeElement.focus(), { injector: this.injector });
  }

  start(): void {
    if (!this.reviewing() || this.validationKey() || this.starting()) return;
    this.starting.set(true);
    this.startError.set(null);
    this.svc.startRollout({
      title: this.title().trim(),
      changeset_ids: this.selectedChangesets().map(c => c.id),
      deployment_ids: this.selectedDeployments().map(d => d.id),
    }).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: detail => {
        this.starting.set(false);
        void this.router.navigate(['/xrm/fleet/rollouts', detail.rollout.id]);
      },
      error: (err: ApiError) => {
        this.starting.set(false);
        this.startError.set(fleetErrorText(this.lang, err));
      },
    });
  }
}

function toggled(set: ReadonlySet<string>, id: string, on: boolean): ReadonlySet<string> {
  const next = new Set(set);
  if (on) next.add(id);
  else next.delete(id);
  return next;
}
