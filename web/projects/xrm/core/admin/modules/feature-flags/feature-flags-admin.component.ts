import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { ApiError } from '@attome/base';
import { FeatureFlagPolicy, FeatureFlagsService, FeatureFlagView } from '@attome/xrm/core/admin/data';

/**
 * Module Management > Feature Flags (M95, D-430). Deployment default and
 * progressive-rollout percentage are editable here; per-user and per-role
 * overrides (`policy.user_overrides`/`policy.role_overrides`) are part of the
 * same stored value but have no picker UI in this first slice — set them via
 * `PUT /api/v1/admin/features/{key}` directly until a targeting picker is
 * built. Every value shown here already reflects `FeatureFlagsService`'s
 * server-side invariant: a flag can never widen what the deployment's
 * licence allows for its module — see `attome_core::feature_flag_store`.
 */
@Component({
  selector: 'xrm-feature-flags-admin',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../../../styles/admin-page.css', './feature-flags-admin.component.css'],
  templateUrl: './feature-flags-admin.component.html',
})
export class FeatureFlagsAdminComponent {
  private readonly service = inject(FeatureFlagsService);

  readonly loading = signal(true);
  readonly savingKey = signal<string | null>(null);
  readonly items = signal<FeatureFlagView[]>([]);
  readonly error = signal<string | null>(null);
  readonly savedKey = signal<string | null>(null);

  constructor() {
    this.load();
  }

  load(): void {
    this.loading.set(true);
    this.error.set(null);
    this.service.listAdmin().subscribe({
      next: res => {
        this.items.set(res.items);
        this.loading.set(false);
      },
      error: (err: ApiError) => {
        this.error.set(err.message);
        this.loading.set(false);
      },
    });
  }

  requiresLabel(item: FeatureFlagView): string {
    return item.requires.length ? `Requires: ${item.requires.join(', ')}` : '';
  }

  percentageValue(item: FeatureFlagView): string {
    return item.policy.percentage === null || item.policy.percentage === undefined
      ? ''
      : String(item.policy.percentage);
  }

  toggleDeployment(item: FeatureFlagView, event: Event): void {
    const on = (event.target as HTMLInputElement).checked;
    this.save(item, { ...item.policy, deployment: on });
  }

  setPercentage(item: FeatureFlagView, event: Event): void {
    const raw = (event.target as HTMLInputElement).value.trim();
    if (raw === '') {
      this.save(item, { ...item.policy, percentage: null });
      return;
    }
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) return;
    const clamped = Math.max(0, Math.min(100, Math.round(parsed)));
    this.save(item, { ...item.policy, percentage: clamped });
  }

  private save(item: FeatureFlagView, policy: FeatureFlagPolicy): void {
    this.savingKey.set(item.key);
    this.error.set(null);
    this.savedKey.set(null);
    this.service.putAdmin(item.key, policy).subscribe({
      next: updated => {
        this.items.update(list => list.map(i => (i.key === updated.key ? updated : i)));
        this.savingKey.set(null);
        this.savedKey.set(item.key);
        // Every `*xrmFeatureFlag` reader (this tab and, on its own next
        // check, any other) should see the new value without a reload.
        this.service.refresh().subscribe();
      },
      error: (err: ApiError) => {
        this.error.set(err.message);
        this.savingKey.set(null);
      },
    });
  }
}
