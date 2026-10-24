import { ChangeDetectionStrategy, Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { MasterDataService, type MasterXrefGolden } from '@attome/xrm/core/admin/data';

/**
 * L1-T9 — find the golden record of a source system's id: the entity, the
 * system and the id it gave the record. The answer links to the record's
 * form; a record the person cannot read is not found.
 */
@Component({
  selector: 'xrm-master-xref-search',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, TranslatePipe],
  styleUrl: './master-data.css',
  template: `
    <form class="md-xref" (ngSubmit)="search()" data-testid="xref-form">
      <label>{{ 'masterData.xref.entity' | translate }}
        <input name="entity" dir="ltr" required class="md-mono" data-testid="xref-entity"
               [ngModel]="entity()" (ngModelChange)="entity.set($event)" />
      </label>
      <label>{{ 'masterData.xref.system' | translate }}
        <input name="system" dir="ltr" required data-testid="xref-system"
               [ngModel]="system()" (ngModelChange)="system.set($event)" />
      </label>
      <label>{{ 'masterData.xref.externalId' | translate }}
        <input name="externalId" dir="ltr" required class="md-mono" data-testid="xref-id"
               [ngModel]="externalId()" (ngModelChange)="externalId.set($event)" />
      </label>
      <button type="submit" class="btn btn-primary" data-testid="xref-search"
              [disabled]="!entity().trim() || !system().trim() || !externalId().trim()">
        {{ 'masterData.xref.search' | translate }}
      </button>
    </form>
    @if (result(); as r) {
      <p class="md-notice" role="status" data-testid="xref-result">
        <a [routerLink]="['/r', found(), r.golden_id]">{{ 'masterData.xref.open' | translate }}</a>
        · {{ 'masterData.status.' + r.status | translate }}
      </p>
    }
    @if (error(); as e) {
      <p class="md-error" role="alert" data-testid="xref-error">{{ e }}</p>
    }
  `,
})
export class XrefSearchComponent {
  private readonly lang = inject(LangService);
  private readonly svc = inject(MasterDataService);
  private readonly destroyRef = inject(DestroyRef);

  readonly entity = signal('');
  readonly system = signal('');
  readonly externalId = signal('');
  readonly result = signal<MasterXrefGolden | null>(null);
  /** The entity the shown result belongs to. */
  readonly found = signal('');
  readonly error = signal<string | null>(null);

  search(): void {
    const entity = this.entity().trim();
    this.result.set(null);
    this.error.set(null);
    this.svc.lookup(entity, this.system().trim(), this.externalId().trim())
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: r => {
          this.found.set(entity);
          this.result.set(r);
        },
        error: (e: ApiError) => this.error.set(e.status === 404
          ? this.lang.translate('masterData.xref.notFound')
          : this.lang.errorText(e)),
      });
  }
}
