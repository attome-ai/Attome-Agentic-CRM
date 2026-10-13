import { ChangeDetectionStrategy, Component, computed, inject, input } from '@angular/core';
import { TranslatePipe } from '@attome/base';
import { ChangesetContextService } from '@attome/xrm/core/admin/data';

/** The four owner layers (migration 0520's CHECK), lowest first. */
export const OWNER_LAYERS = ['platform', 'product', 'project', 'customer'] as const;
export type OwnerLayer = typeof OWNER_LAYERS[number];

/**
 * Automatic changesets' layer (`metadata.changesets.auto_layer`, `project` in
 * Solution 7 Phase 1): what a write is recorded as when no changeset applies.
 */
const DEFAULT_EDITING_LAYER: OwnerLayer = 'project';

/** Literal keys per layer, so the catalog coverage specs can see each one. */
const LAYER_KEYS: Record<OwnerLayer, string> = {
  platform: 'changesets.layer.platform',
  product:  'changesets.layer.product',
  project:  'changesets.layer.project',
  customer: 'changesets.layer.customer',
};

function asLayer(value: string | null | undefined): OwnerLayer | null {
  return value && (OWNER_LAYERS as readonly string[]).includes(value) ? value as OwnerLayer : null;
}

/**
 * Solution 7 (D-785) — the read-only `owner_layer` of a metadata row (entity,
 * field, view, sidebar item, role, …), and, when the row belongs to a layer
 * other than the one being edited, why a save will be refused (409
 * `layer_mismatch`).
 *
 * The editing layer is the effective changeset's (`ChangesetContextService`),
 * or `project` when none applies. `editingLayer` overrides it for a host that
 * knows better. Presentation only: the server's recorder enforces the rule.
 *
 * `compact` (list rows) shows the layer and a lock; the refusal reason is the
 * tooltip and screen-reader text. `full` (editor headers) also prints it.
 * Colour is never the only signal: the layer is text, the lock is an icon.
 */
@Component({
  selector: 'xrm-owner-layer-badge',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./owner-layer-badge.component.css'],
  templateUrl: './owner-layer-badge.component.html',
})
export class OwnerLayerBadgeComponent {
  private readonly changesets = inject(ChangesetContextService);

  /** The row's `owner_layer`; nothing renders for an absent or unknown value. */
  readonly layer = input<string | null | undefined>(null);
  /** Overrides the effective changeset's layer. */
  readonly editingLayer = input<string | null | undefined>(undefined);
  readonly variant = input<'compact' | 'full'>('compact');

  readonly owner = computed(() => asLayer(this.layer()));

  readonly editing = computed<OwnerLayer>(() => {
    const override = this.editingLayer();
    return asLayer(override === undefined ? this.changesets.editingLayer() : override) ?? DEFAULT_EDITING_LAYER;
  });

  /** A save of this row would be refused with `layer_mismatch`. */
  readonly locked = computed(() => {
    const owner = this.owner();
    return owner !== null && owner !== this.editing();
  });

  readonly ownerKey   = computed(() => { const o = this.owner(); return o ? LAYER_KEYS[o] : ''; });
  readonly editingKey = computed(() => LAYER_KEYS[this.editing()]);
}
