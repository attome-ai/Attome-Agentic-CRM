import {
  ChangeDetectionStrategy, Component, DestroyRef, effect, inject, input, output, signal, untracked,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { LangService, LocalDatePipe, LocalNumberPipe, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import {
  DataCatalogService, type CatalogAssetPage, type CatalogAssetSummary,
} from '@attome/xrm/core/admin/data';
import { DescriptionEditorComponent } from './description-editor.component';

/**
 * The asset page's facts as the screen reads them. The server sends each as
 * free-form JSON owned by its feature (L3 domains, C10 terms, L2 quality, L6
 * profiles, L5 lineage, the usage rollup, certification, the change log), so
 * this is the shape those features write.
 */
export interface AssetView {
  asset: CatalogAssetSummary;
  domain: { name?: string; description?: string | null } | null;
  label: string | null;
  terms: { term?: string; definition?: string | null; status?: string }[] | null;
  quality: { dimension?: string; score?: number; period?: string }[] | null;
  profile: { row_count?: number; completed_at?: string } | null;
  lineage: { from_kind?: string; from_label?: string; to_attribute?: string | null }[] | null;
  usage: {
    record_count?: number; last_write_at?: string | null; search_impressions_30d?: number;
    unused?: boolean; readers?: Record<string, number>; computed_at?: string;
  } | null;
  certification: { status?: string; certified_at?: string | null } | null;
  history: { change_kind?: string; created_at?: string }[] | null;
}

/** The page as its view. Pure. */
export function assetView(page: CatalogAssetPage): AssetView {
  return page as unknown as AssetView;
}

/** An asset's name in the reader's language, falling back to the other, then its ref. Pure. */
export function assetName(a: Pick<CatalogAssetSummary, 'name_en' | 'name_ar' | 'ref'>, rtl: boolean): string {
  const first = rtl ? a.name_ar : a.name_en;
  const second = rtl ? a.name_en : a.name_ar;
  return first || second || a.ref;
}

/**
 * L4-T6: one asset's page: its description (with the editor), domain,
 * label, glossary terms, quality, profile, what reads it, usage,
 * certification and recent changes. Each panel shows only when its feature
 * has something to say about the asset.
 */
@Component({
  selector: 'xrm-catalog-asset-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe, LocalDatePipe, LocalNumberPipe, DescriptionEditorComponent],
  styleUrls: ['./catalog-assets.css'],
  template: `
    <section class="card" aria-live="polite" data-testid="asset-page">
      @if (loading()) {
        <p class="state-msg">{{ 'governance.common.loading' | translate }}</p>
      } @else if (error()) {
        <p class="error-msg" role="alert">{{ error() }}</p>
      } @else if (view(); as v) {
        <div class="section-header">
          <h3>{{ name(v.asset) }}</h3>
          <button type="button" class="btn-text" (click)="closed.emit()">
            <i class="las la-times" aria-hidden="true"></i> {{ 'governance.common.close' | translate }}
          </button>
        </div>
        <p class="gov-muted">
          {{ 'governance.catalog.assets.kinds.' + v.asset.kind | translate }} ·
          <span class="cell-mono">{{ v.asset.ref }}</span> ·
          {{ 'governance.catalog.assets.status.' + v.asset.description_status | translate }}
        </p>

        <div class="ca-panel" data-panel="description">
          <h4>{{ 'governance.catalog.assets.description' | translate }}</h4>
          @if (v.asset.description_en) { <p lang="en" dir="ltr">{{ v.asset.description_en }}</p> }
          @if (v.asset.description_ar) { <p lang="ar" dir="rtl">{{ v.asset.description_ar }}</p> }
          <xrm-catalog-description-editor [asset]="v.asset" (changed)="updated($event)" />
        </div>

        @if (v.domain; as d) {
          <div class="ca-panel" data-panel="domain">
            <h4>{{ 'governance.catalog.assets.domain' | translate }}</h4>
            <p>{{ d.name }}</p>
            @if (d.description) { <p class="gov-muted">{{ d.description }}</p> }
          </div>
        }
        @if (v.label; as l) {
          <div class="ca-panel" data-panel="label">
            <h4>{{ 'governance.catalog.assets.label' | translate }}</h4>
            <span class="badge">{{ l }}</span>
          </div>
        }
        @if (v.terms?.length) {
          <div class="ca-panel" data-panel="terms">
            <h4>{{ 'governance.catalog.glossary' | translate }}</h4>
            <ul>
              @for (t of v.terms ?? []; track t.term) {
                <li><strong>{{ t.term }}</strong> @if (t.definition) { : {{ t.definition }} }</li>
              }
            </ul>
          </div>
        }
        @if (v.quality?.length) {
          <div class="ca-panel" data-panel="quality">
            <h4>{{ 'governance.catalog.assets.quality' | translate }}</h4>
            <ul>
              @for (q of v.quality ?? []; track q.dimension) {
                <li>{{ q.dimension }}: {{ (q.score ?? 0) | localNumber }}</li>
              }
            </ul>
          </div>
        }
        @if (v.profile; as p) {
          <div class="ca-panel" data-panel="profile">
            <h4>{{ 'governance.catalog.profile.title' | translate }}</h4>
            <p>
              {{ 'governance.catalog.profile.allRows' | translate: { rows: p.row_count } }}
              @if (p.completed_at) { · {{ p.completed_at | localDate: { dateStyle: 'medium' } }} }
            </p>
          </div>
        }
        @if (v.lineage?.length) {
          <div class="ca-panel" data-panel="lineage">
            <h4>{{ 'governance.catalog.lineage' | translate }}</h4>
            <ul>
              @for (r of v.lineage ?? []; track $index) {
                <li>
                  {{ 'governance.catalog.lineageKinds.' + r.from_kind | translate }}: {{ r.from_label }}
                  @if (r.to_attribute) { <span class="cell-mono">({{ r.to_attribute }})</span> }
                </li>
              }
            </ul>
          </div>
        }
        @if (v.usage; as u) {
          <div class="ca-panel" data-panel="usage">
            <h4>{{ 'governance.catalog.usage' | translate }}</h4>
            <dl class="dc-facts">
              <dt>{{ 'governance.catalog.recordCount' | translate }}</dt>
              <dd>{{ (u.record_count ?? 0) | localNumber }}</dd>
              <dt>{{ 'governance.catalog.impressions' | translate }}</dt>
              <dd>{{ (u.search_impressions_30d ?? 0) | localNumber }}</dd>
            </dl>
            @if (u.unused) {
              <span class="badge" data-testid="asset-unused">{{ 'governance.catalog.assets.unused' | translate }}</span>
            }
          </div>
        }
        @if (v.certification; as c) {
          <div class="ca-panel" data-panel="certification">
            <h4>{{ 'governance.catalog.assets.certification' | translate }}</h4>
            <span class="badge">{{ c.status }}</span>
          </div>
        }
        @if (v.history?.length) {
          <div class="ca-panel" data-panel="history">
            <h4>{{ 'governance.catalog.assets.history' | translate }}</h4>
            <ul>
              @for (h of v.history ?? []; track $index) {
                <li>{{ h.change_kind }} · {{ h.created_at | localDate: { dateStyle: 'medium', timeStyle: 'short' } }}</li>
              }
            </ul>
          </div>
        }
      }
    </section>
  `,
})
export class AssetPageComponent {
  private readonly svc = inject(DataCatalogService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly lang = inject(LangService);

  readonly assetId = input.required<string>();
  readonly closed = output<void>();

  readonly view = signal<AssetView | null>(null);
  readonly loading = signal(false);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      const id = this.assetId();
      untracked(() => this.load(id));
    });
  }

  name(a: CatalogAssetSummary): string {
    return assetName(a, this.lang.isRtl());
  }

  /** A saved or approved description: the page shows the server's copy. */
  updated(asset: CatalogAssetSummary): void {
    const v = this.view();
    if (v) this.view.set({ ...v, asset });
  }

  private load(id: string): void {
    this.loading.set(true);
    this.error.set(null);
    this.svc.getAsset(id).pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: page => { this.view.set(assetView(page)); this.loading.set(false); },
      error: (e: ApiError) => { this.error.set(this.lang.errorText(e)); this.loading.set(false); },
    });
  }
}
