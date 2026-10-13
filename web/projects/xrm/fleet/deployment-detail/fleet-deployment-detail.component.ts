import {
  ChangeDetectionStrategy, Component, DestroyRef, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { FleetService } from '../data/fleet.service';
import { fleetErrorText } from '../data/fleet-error-text';
import { fleetLabel, type FleetLabelSet } from '../data/fleet-labels';
import {
  FLEET_ENVIRONMENTS, FLEET_RINGS,
  type ActionView, type DeploymentView, type FleetEnvironment, type FleetRing, type LedgerHeadEntry,
  type UpdateDeploymentBody,
} from '../data/fleet.types';

type Panel = 'none' | 'edit' | 'credential';

function isLedgerEntry(value: unknown): value is LedgerHeadEntry {
  return typeof value === 'object' && value !== null && 'changeset_id' in value;
}

/**
 * `/xrm/fleet/deployments/:id` (D-792 F1): one customer deployment — its
 * registration, its latest check (version, health, ledger head), drift, the
 * console's action log for it, and the three changes the console makes:
 * edit (moving a deployment that holds a credential needs a step-up), set the
 * rollout credential (always a step-up; only the last four characters are
 * ever shown again) and sync now.
 */
@Component({
  selector: 'attome-fleet-deployment-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, LocalDatePipe, LocalNumberPipe, TranslatePipe],
  styleUrls: ['../../styles/admin-page.css', '../fleet.css', './fleet-deployment-detail.component.css'],
  templateUrl: './fleet-deployment-detail.component.html',
})
export class FleetDeploymentDetailComponent {
  private readonly svc = inject(FleetService);
  private readonly lang = inject(LangService);
  private readonly destroyRef = inject(DestroyRef);

  /** Route parameter (`withComponentInputBinding()`). */
  readonly id = input.required<string>();

  readonly environments = FLEET_ENVIRONMENTS;
  readonly rings = FLEET_RINGS;
  readonly dateFmt: Intl.DateTimeFormatOptions = { dateStyle: 'medium', timeStyle: 'short' };
  readonly actionsPageSize = 20;

  readonly deployment = signal<DeploymentView | null>(null);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly syncing = signal(false);

  readonly panel = signal<Panel>('none');
  readonly saving = signal(false);
  readonly formError = signal<string | null>(null);

  // Edit form
  readonly editLabel = signal('');
  readonly editEnvironment = signal<FleetEnvironment>('prod');
  readonly editRing = signal<FleetRing>('broad');
  readonly editBaseUrl = signal('');
  readonly editWindow = signal('');
  readonly editActive = signal(true);

  // Credential form
  readonly clientId = signal('');
  readonly keyId = signal('');
  readonly secret = signal('');
  readonly verify = signal(true);

  // Action log
  readonly actions = signal<ActionView[]>([]);
  readonly actionsTotal = signal(0);
  readonly actionsPage = signal(1);
  readonly actionsLoading = signal(false);
  readonly actionsError = signal<string | null>(null);
  readonly actionsPages = computed(() => Math.max(1, Math.ceil(this.actionsTotal() / this.actionsPageSize)));

  readonly ledgerHead = computed<LedgerHeadEntry[]>(() => {
    const head = this.deployment()?.observation?.ledger_head;
    return Array.isArray(head) ? head.filter(isLedgerEntry) : [];
  });

  readonly canSaveCredential = computed(() =>
    this.clientId().trim().length > 0 && this.keyId().trim().length > 0 && this.secret().length > 0);

  constructor() {
    effect(() => {
      const id = this.id();
      untracked(() => {
        this.panel.set('none');
        this.notice.set(null);
        this.load(id);
        this.actionsPage.set(1);
        this.loadActions(id);
      });
    });
  }

  text(set: FleetLabelSet, value: string | null | undefined): string {
    return fleetLabel(this.lang, set, value);
  }

  driftTone(status: string): string {
    switch (status) {
      case 'in_sync':  return 'fleet-pill--ok';
      case 'diverged':
      case 'schema_dirty': return 'fleet-pill--bad';
      default: return 'fleet-pill--warn';
    }
  }

  reload(): void {
    this.load(this.id());
    this.loadActions(this.id());
  }

  private load(id: string): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.getDeployment(id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: d => {
        if (id !== this.id()) return; // a late answer for the previous deployment
        this.deployment.set(d);
        this.loading.set(false);
      },
      error: (err: ApiError) => {
        if (id !== this.id()) return;
        this.error.set(fleetErrorText(this.lang, err));
        this.loading.set(false);
      },
    });
  }

  loadActions(id: string = this.id()): void {
    this.actionsLoading.set(true);
    this.actionsError.set(null);
    this.svc.listActions(id, this.actionsPage(), this.actionsPageSize)
      .pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
        next: res => {
          if (id !== this.id()) return;
          this.actions.set(res.items);
          this.actionsTotal.set(res.total);
          this.actionsLoading.set(false);
        },
        error: (err: ApiError) => {
          this.actionsError.set(fleetErrorText(this.lang, err));
          this.actionsLoading.set(false);
        },
      });
  }

  previousActions(): void {
    if (this.actionsPage() <= 1 || this.actionsLoading()) return;
    this.actionsPage.update(p => p - 1);
    this.loadActions();
  }

  nextActions(): void {
    if (this.actionsPage() >= this.actionsPages() || this.actionsLoading()) return;
    this.actionsPage.update(p => p + 1);
    this.loadActions();
  }

  sync(): void {
    if (this.syncing()) return;
    this.syncing.set(true);
    this.notice.set(null);
    this.error.set(null);
    this.svc.syncDeployment(this.id()).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: d => {
        this.syncing.set(false);
        this.deployment.set(d);
        this.notice.set(this.lang.translate('fleet.deployments.synced', { name: d.label }));
        this.loadActions();
      },
      error: (err: ApiError) => {
        this.syncing.set(false);
        this.error.set(fleetErrorText(this.lang, err));
      },
    });
  }

  openEdit(): void {
    const d = this.deployment();
    if (!d) return;
    this.editLabel.set(d.label);
    this.editEnvironment.set(d.environment as FleetEnvironment);
    this.editRing.set(d.ring as FleetRing);
    this.editBaseUrl.set(d.base_url);
    this.editWindow.set(d.maintenance_window ?? '');
    this.editActive.set(d.is_active);
    this.formError.set(null);
    this.panel.set('edit');
  }

  openCredential(): void {
    const d = this.deployment();
    this.clientId.set(d?.s2s_client_id ?? '');
    this.keyId.set(d?.s2s_key_id ?? '');
    this.secret.set('');
    this.verify.set(true);
    this.formError.set(null);
    this.panel.set('credential');
  }

  closePanel(): void {
    this.panel.set('none');
    this.secret.set('');
  }

  /** Sends only what changed, with the `row_version` the form was opened on. */
  saveEdit(): void {
    const d = this.deployment();
    if (!d || this.saving()) return;
    const body: UpdateDeploymentBody = { row_version: d.row_version };
    const label = this.editLabel().trim();
    if (label !== d.label) body.label = label;
    if (this.editEnvironment() !== d.environment) body.environment = this.editEnvironment();
    if (this.editRing() !== d.ring) body.ring = this.editRing();
    const baseUrl = this.editBaseUrl().trim();
    if (baseUrl !== d.base_url) body.base_url = baseUrl;
    const maintenance = this.editWindow().trim();
    if (maintenance !== (d.maintenance_window ?? '')) body.maintenance_window = maintenance;
    if (this.editActive() !== d.is_active) body.is_active = this.editActive();
    this.saving.set(true);
    this.formError.set(null);
    this.svc.updateDeployment(d.id, body).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: updated => this.saved(updated, 'fleet.detail.savedEdit'),
      error: (err: ApiError) => this.failed(err),
    });
  }

  saveCredential(): void {
    const d = this.deployment();
    if (!d || !this.canSaveCredential() || this.saving()) return;
    this.saving.set(true);
    this.formError.set(null);
    this.svc.setCredential(
      d.id, d.row_version,
      { s2s_client_id: this.clientId().trim(), s2s_key_id: this.keyId().trim(), secret: this.secret() },
      this.verify(),
    ).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: updated => this.saved(updated, 'fleet.detail.savedCredential'),
      error: (err: ApiError) => this.failed(err),
    });
  }

  private saved(updated: DeploymentView, noticeKey: string): void {
    this.saving.set(false);
    this.secret.set('');
    this.deployment.set(updated);
    this.panel.set('none');
    this.notice.set(this.lang.translate(noticeKey));
    this.loadActions();
  }

  private failed(err: ApiError): void {
    this.saving.set(false);
    if (err.kind === 'version_conflict') {
      // Someone (or another tab) changed it: show the fresh row, keep the form.
      this.formError.set(this.lang.translate('fleet.detail.versionConflict'));
      this.load(this.id());
      return;
    }
    this.formError.set(fleetErrorText(this.lang, err));
  }
}
