import { ChangeDetectionStrategy, Component, DestroyRef, computed, inject } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { TranslatePipe } from '@attome/base';
import { AccessService } from '@attome/xrm/core/access/data';
import { ChangesetContextService } from '@attome/xrm/core/admin/data';
import { EMPTY, switchMap } from 'rxjs';

const ADMIN_PRIVILEGE = 'system.admin';

/** Literal keys per layer (catalog coverage sees each one). */
const LAYER_KEYS: Record<string, string> = {
  platform: 'changesets.layer.platform',
  product:  'changesets.layer.product',
  project:  'changesets.layer.project',
  customer: 'changesets.layer.customer',
};

let nextId = 0;

/**
 * Solution 7 (D-785) — the header's "open changeset" indicator: which open
 * changeset metadata edits record into, with a picker that sets
 * `X-Attome-Changeset` (through `ChangesetContextService` → `ApiService`).
 *
 * Development only, without a build flag: the list route sits under the
 * metadata authoring prefixes, so a production deployment answers 403
 * `metadata_authoring_locked` and the indicator stays hidden. It is also
 * admin-only (the route is `system.admin`), so it asks only once `whoami`
 * says the user is one — a non-admin never sends the request.
 */
@Component({
  selector: 'xrm-changeset-indicator',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./changeset-indicator.component.css'],
  templateUrl: './changeset-indicator.component.html',
})
export class ChangesetIndicatorComponent {
  private readonly access     = inject(AccessService);
  private readonly destroyRef = inject(DestroyRef);
  readonly ctx = inject(ChangesetContextService);

  readonly selectId = `xrm-changeset-pick-${nextId++}`;

  readonly visible = computed(() => {
    const status = this.ctx.status();
    return this.access.hasPrivilege(ADMIN_PRIVILEGE) && (status === 'ready' || status === 'error');
  });

  /** The changeset a write records into when nothing is picked (the caller's only open one). */
  readonly fallback = computed(() => (this.ctx.selected() ? null : this.ctx.effective()));

  constructor() {
    this.access.ready().pipe(
      switchMap(() => (this.access.hasPrivilege(ADMIN_PRIVILEGE) ? this.ctx.refresh() : EMPTY)),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe();
  }

  layerKey(layer: string): string {
    return LAYER_KEYS[layer] ?? layer;
  }

  onPick(event: Event): void {
    const value = (event.target as HTMLSelectElement | null)?.value ?? '';
    this.ctx.select(value || null);
  }

  refresh(): void {
    this.ctx.refresh().pipe(takeUntilDestroyed(this.destroyRef)).subscribe();
  }
}
