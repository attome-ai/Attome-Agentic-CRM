import {
  ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fleetErrorText } from '../data/fleet-error-text';
import { fleetLabel, type FleetLabelSet } from '../data/fleet-labels';
import {
  FLEET_ENVIRONMENTS, FLEET_RINGS,
  type DeploymentView, type FleetEnvironment, type FleetRing, type RegisterDeploymentBody,
} from '../data/fleet.types';

/**
 * `/xrm/fleet/deployments` (D-792 F1): every registered customer deployment
 * with its latest check (version, ready, open items) and its drift against
 * this build; Sync all; Register a deployment (optionally with its rollout
 * credential, which needs a fresh step-up). One-based paging.
 */
@Component({
  selector: 'attome-fleet-deployments',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', '../fleet.css', './fleet-deployments.component.css'],
  templateUrl: './fleet-deployments.component.html',
})
export class FleetDeploymentsComponent implements OnInit {
  private readonly svc = inject(FleetService);
  private readonly lang = inject(LangService);
  private readonly router = inject(Router);
  private readonly destroyRef = inject(DestroyRef);

  readonly environments = FLEET_ENVIRONMENTS;
  readonly rings = FLEET_RINGS;
  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly pageSize = 25;

  readonly includeInactive = signal(false);
  readonly deployments = signal<DeploymentView[]>([]);
  readonly total = signal(0);
  readonly page = signal(1);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly syncingAll = signal(false);
  readonly syncingId = signal<string | null>(null);

  readonly pages = computed(() => Math.max(1, Math.ceil(this.total() / this.pageSize)));
  readonly hasPrevious = computed(() => this.page() > 1);
  readonly hasNext = computed(() => this.page() < this.pages());

  // ── Register form ───────────────────────────────────────────────────────
  readonly formOpen = signal(false);
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);
  readonly projectCode = signal('');
  readonly label = signal('');
  readonly environment = signal<FleetEnvironment>('prod');
  readonly ring = signal<FleetRing>('broad');
  readonly baseUrl = signal('');
  readonly maintenanceWindow = signal('');
  readonly withCredential = signal(false);
  readonly clientId = signal('');
  readonly keyId = signal('');
  readonly secret = signal('');

  readonly canRegister = computed(() =>
    this.projectCode().trim().length > 0
    && this.label().trim().length > 0
    && this.baseUrl().trim().length > 0
    && (!this.withCredential()
      || (this.clientId().trim().length > 0 && this.keyId().trim().length > 0 && this.secret().length > 0)));

  ngOnInit(): void {
    this.load();
  }

  text(set: FleetLabelSet, value: string | null | undefined): string {
    return fleetLabel(this.lang, set, value);
  }

  /** `fleet-pill--ok|warn|bad` for a drift status. */
  driftTone(status: string): string {
    switch (status) {
      case 'in_sync':  return 'fleet-pill--ok';
      case 'diverged':
      case 'schema_dirty': return 'fleet-pill--bad';
      default: return 'fleet-pill--warn';
    }
  }

  toggleInactive(value: boolean): void {
    this.includeInactive.set(value);
    this.page.set(1);
    this.load();
  }

  previous(): void {
    if (!this.hasPrevious() || this.loading()) return;
    this.page.update(p => p - 1);
    this.load();
  }

  next(): void {
    if (!this.hasNext() || this.loading()) return;
    this.page.update(p => p + 1);
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.listDeployments(this.includeInactive(), this.page(), this.pageSize)
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: res => {
          this.deployments.set(res.items);
          this.total.set(res.total);
          this.loading.set(false);
        },
        error: (err: ApiError) => {
          this.error.set(fleetErrorText(this.lang, err));
          this.loading.set(false);
        },
      });
  }

  syncAll(): void {
    if (this.syncingAll()) return;
    this.syncingAll.set(true);
    this.notice.set(null);
    this.error.set(null);
    this.svc.syncAll().pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: res => {
        this.syncingAll.set(false);
        this.notice.set(this.lang.translate(res.queued ? 'fleet.deployments.syncQueued' : 'fleet.deployments.syncAlreadyQueued'));
      },
      error: (err: ApiError) => {
        this.syncingAll.set(false);
        this.error.set(fleetErrorText(this.lang, err));
      },
    });
  }

  syncOne(deployment: DeploymentView): void {
    if (this.syncingId()) return;
    this.syncingId.set(deployment.id);
    this.notice.set(null);
    this.error.set(null);
    this.svc.syncDeployment(deployment.id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: updated => {
        this.syncingId.set(null);
        this.deployments.update(list => list.map(d => (d.id === updated.id ? updated : d)));
        this.notice.set(this.lang.translate('fleet.deployments.synced', { name: updated.label }));
      },
      error: (err: ApiError) => {
        this.syncingId.set(null);
        this.error.set(fleetErrorText(this.lang, err));
      },
    });
  }

  openForm(): void {
    this.formOpen.set(true);
    this.formError.set(null);
  }

  closeForm(): void {
    this.formOpen.set(false);
    this.secret.set('');
  }

  register(): void {
    if (!this.canRegister() || this.saving()) return;
    const body: RegisterDeploymentBody = {
      project_code: this.projectCode().trim(),
      label: this.label().trim(),
      environment: this.environment(),
      ring: this.ring(),
      base_url: this.baseUrl().trim(),
      maintenance_window: this.maintenanceWindow().trim() || null,
      credential: this.withCredential()
        ? { s2s_client_id: this.clientId().trim(), s2s_key_id: this.keyId().trim(), secret: this.secret() }
        : null,
    };
    this.saving.set(true);
    this.formError.set(null);
    this.svc.registerDeployment(body).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: created => {
        this.saving.set(false);
        // The secret never stays in the page once it has been sent.
        this.secret.set('');
        this.formOpen.set(false);
        void this.router.navigate(['/xrm/fleet/deployments', created.id]);
      },
      error: (err: ApiError) => {
        this.saving.set(false);
        this.formError.set(fleetErrorText(this.lang, err));
      },
    });
  }
}
