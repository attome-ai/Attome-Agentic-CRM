import {
  ChangeDetectionStrategy, Component, DestroyRef, effect, inject, input, output, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { DataCatalogService, type CatalogAssetSummary } from '@attome/xrm/core/admin/data';

/**
 * L4-T6: an asset's description in English and Arabic, side by side. Saving
 * makes a draft (at the asset's `row_version`, so a concurrent edit is a
 * conflict, not a lost write); a builder approves a draft. Hidden on a phone,
 * where the catalogue is read-only.
 */
@Component({
  selector: 'xrm-catalog-description-editor',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['./catalog-assets.css'],
  template: `
    <form class="ca-edit-only" (ngSubmit)="save()" data-testid="description-editor">
      <div class="ca-desc">
        <label>
          <span>{{ 'governance.catalog.assets.descriptionEn' | translate }}</span>
          <textarea name="en" dir="ltr" lang="en" [ngModel]="en()" (ngModelChange)="en.set($event)"
                    data-testid="description-en"></textarea>
        </label>
        <label>
          <span>{{ 'governance.catalog.assets.descriptionAr' | translate }}</span>
          <textarea name="ar" dir="rtl" lang="ar" [ngModel]="ar()" (ngModelChange)="ar.set($event)"
                    data-testid="description-ar"></textarea>
        </label>
      </div>
      @if (error()) { <p class="error-msg" role="alert">{{ error() }}</p> }
      <div class="ca-actions">
        <button type="submit" class="btn-primary" [disabled]="busy()" data-testid="description-save">
          {{ 'governance.catalog.assets.saveDraft' | translate }}
        </button>
        @if (asset().description_status === 'draft') {
          <button type="button" class="btn-ghost" [disabled]="busy()" (click)="approve()"
                  data-testid="description-approve">
            {{ 'governance.catalog.assets.approve' | translate }}
          </button>
        }
      </div>
    </form>
  `,
})
export class DescriptionEditorComponent {
  private readonly svc = inject(DataCatalogService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly lang = inject(LangService);

  readonly asset = input.required<CatalogAssetSummary>();
  /** The asset as the server returned it after a save or an approval. */
  readonly changed = output<CatalogAssetSummary>();

  readonly en = signal('');
  readonly ar = signal('');
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      const a = this.asset();
      this.en.set(a.description_en ?? '');
      this.ar.set(a.description_ar ?? '');
    });
  }

  save(): void {
    const a = this.asset();
    this.run(this.svc.setDescription(a.id, a.row_version, {
      description_en: this.en().trim() || null,
      description_ar: this.ar().trim() || null,
    }));
  }

  approve(): void {
    const a = this.asset();
    this.run(this.svc.approveDescription(a.id, a.row_version));
  }

  private run(call: ReturnType<DataCatalogService['setDescription']>): void {
    this.busy.set(true);
    this.error.set(null);
    call.pipe(takeUntilDestroyed(this.destroyRef)).subscribe({
      next: asset => { this.busy.set(false); this.changed.emit(asset); },
      error: (e: ApiError) => { this.busy.set(false); this.error.set(this.lang.errorText(e)); },
    });
  }
}
