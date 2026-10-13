import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { TranslatePipe } from '@attome/base';
import { EntityService, entityFormRoute } from '@attome/xrm/core/entity';
import { ChoicePillComponent } from '@attome/xrm/core/generic/components';
import type { ChoicePillStyle } from '@attome/xrm/core/generic/components';

interface PolicyRow {
  id:            string;
  title:         string;
  status:        string | null;
  version:       string | null;
  effectiveDate: string | null;
  expiryDate:    string | null;
}

const STATUS_STYLE: Record<string, ChoicePillStyle> = {
  draft:   { color: '#94a3b8' },
  active:  { color: '#22c55e' },
  expired: { color: '#ef4444' },
  retired: { color: '#64748b' },
};

/** Days before `expiryDate` this view starts flagging a policy as "expiring
 * soon" — a bright but not yet expired policy needs an owner's attention
 * before it lapses. Phase 2 (M51) turns this into an actual reminder job;
 * this is the read-only visual signal until then. */
const EXPIRING_SOON_DAYS = 30;

/**
 * `grc_policy`'s list-page override (M20-grc.md Phase 1 checklist) — the
 * generic metadata-driven grid already renders every field this entity
 * declares, but a GRC policy register is read far more often for "what's
 * expiring / what's not yet active" than for arbitrary column filtering, so
 * this view surfaces status and days-to-expiry directly instead of leaving
 * them as two more grid columns among a dozen.
 *
 * Deliberately a thin, standalone table (not `EntityListComponent` wrapped
 * the way `ProjectListComponent` wraps the generic grid for `attome_project`):
 * that component's filter/sort/bulk-action surface is built for a
 * general-purpose entity grid, and none of it is what a policy register
 * actually wants highlighted. "New"/"Edit" still route to the generic
 * create/edit form — this view only replaces the *reading* experience.
 */
@Component({
  selector: 'attome-grc-policy-list',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, ChoicePillComponent],
  templateUrl: './policy-list.component.html',
  styleUrl: './policy-list.component.css',
})
export class PolicyListComponent {
  private readonly entityService = inject(EntityService);
  private readonly router = inject(Router);

  protected readonly rows = signal<PolicyRow[]>([]);
  protected readonly loading = signal(true);
  protected readonly error = signal<string | null>(null);

  constructor() {
    this.load();
  }

  private load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.entityService.list('grc_policy', { limit: 200, offset: 0 }).subscribe({
      next: res => {
        this.rows.set(
          res.data.map(r => ({
            id: r.id,
            title: String(r.data['title'] ?? ''),
            status: (r.data['status'] as string | null) ?? null,
            version: (r.data['version'] as string | null) ?? null,
            effectiveDate: (r.data['effective_date'] as string | null) ?? null,
            expiryDate: (r.data['expiry_date'] as string | null) ?? null,
          })),
        );
        this.loading.set(false);
      },
      error: () => {
        this.error.set('grc.policyList.loadError');
        this.loading.set(false);
      },
    });
  }

  protected statusStyle(status: string | null): ChoicePillStyle | null {
    return status ? (STATUS_STYLE[status] ?? null) : null;
  }

  /** `true` when `expiryDate` falls within `EXPIRING_SOON_DAYS` from now, or
   * has already passed — the two situations a policy owner needs to see at
   * a glance without opening the record. */
  protected isExpiringSoon(expiryDate: string | null): boolean {
    if (!expiryDate) return false;
    const days = (new Date(expiryDate).getTime() - Date.now()) / 86_400_000;
    return days <= EXPIRING_SOON_DAYS;
  }

  protected isExpired(expiryDate: string | null): boolean {
    if (!expiryDate) return false;
    return new Date(expiryDate).getTime() < Date.now();
  }

  protected openPolicy(id: string): void {
    void this.router.navigate(entityFormRoute('grc_policy'), { queryParams: { id } });
  }

  protected createPolicy(): void {
    void this.router.navigate(entityFormRoute('grc_policy'));
  }
}
