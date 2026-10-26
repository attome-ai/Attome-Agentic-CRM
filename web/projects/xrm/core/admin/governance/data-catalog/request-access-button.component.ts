import {
  ChangeDetectionStrategy, Component, DestroyRef, inject, input, signal,
} from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormsModule } from '@angular/forms';
import { Observable, map, of, switchMap, throwError } from 'rxjs';
import { LangService, TranslatePipe } from '@attome/base';
import type { ApiError } from '@attome/base';
import { DataCatalogService, type CatalogAccessRequest } from '@attome/xrm/core/admin/data';

/** No asset to ask for. */
const NOT_FOUND: ApiError = { kind: 'not_found', message: '', status: 404 };

/**
 * L4-T6: asks for access to something the person cannot read but the
 * deployment shows exists (`catalog.show_hidden_existence`, L4-T3): a hidden
 * attribute names its entity, and the request goes to that entity's asset
 * with the attribute in the reason. The asset's owner decides; the grant is a
 * role (Q10). One pending request per person and asset: asking again says so.
 */
@Component({
  selector: 'xrm-catalog-request-access',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  styleUrls: ['./catalog-assets.css'],
  template: `
    @if (state() === 'sent') {
      <span class="badge" role="status" data-testid="access-requested">
        {{ 'governance.catalog.assets.accessRequested' | translate }}
      </span>
    } @else if (state() === 'open' || state() === 'sending') {
      <form class="ca-request" (ngSubmit)="send()" data-testid="access-form">
        <label>
          <span>{{ 'governance.catalog.assets.accessReason' | translate }}</span>
          <textarea name="reason" maxlength="1000" [ngModel]="reason()" (ngModelChange)="reason.set($event)"
                    data-testid="access-reason"></textarea>
        </label>
        @if (error()) { <p class="error-msg" role="alert">{{ error() }}</p> }
        <div class="ca-actions">
          <button type="submit" class="btn-primary" [disabled]="state() === 'sending' || !reason().trim()"
                  data-testid="access-send">
            {{ 'governance.catalog.assets.accessSend' | translate }}
          </button>
          <button type="button" class="btn-ghost" (click)="state.set('closed')">
            {{ 'governance.common.cancel' | translate }}
          </button>
        </div>
      </form>
    } @else {
      <button type="button" class="btn-text" (click)="state.set('open')" data-testid="access-open">
        <i class="las la-key" aria-hidden="true"></i> {{ 'governance.catalog.assets.requestAccess' | translate }}
      </button>
    }
  `,
})
export class RequestAccessButtonComponent {
  private readonly svc = inject(DataCatalogService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly lang = inject(LangService);

  /** The asset to ask for, when known. */
  readonly assetId = input<string | null>(null);
  /** Otherwise the entity whose asset is asked for. */
  readonly entity = input<string | null>(null);
  /** A hidden attribute of that entity, named in the reason. */
  readonly attribute = input<string | null>(null);

  readonly state = signal<'closed' | 'open' | 'sending' | 'sent'>('closed');
  readonly reason = signal('');
  readonly error = signal<string | null>(null);

  send(): void {
    const field = this.attribute();
    const reason = field ? `${this.reason().trim()} (${field})` : this.reason().trim();
    this.state.set('sending');
    this.error.set(null);
    this.target().pipe(
      switchMap(id => this.svc.requestAccess(id, reason)),
      takeUntilDestroyed(this.destroyRef),
    ).subscribe({
      next: (_: CatalogAccessRequest) => this.state.set('sent'),
      error: (e: ApiError) => {
        // A pending request already exists: that is what the person wanted.
        if (e.status === 409) { this.state.set('sent'); return; }
        this.state.set('open');
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  /** The asset id: the one given, or the entity's own asset. */
  private target(): Observable<string> {
    const id = this.assetId();
    if (id) return of(id);
    const entity = this.entity();
    if (!entity) return throwError(() => NOT_FOUND);
    return this.svc.searchAssets({ q: entity, kind: 'entity' }, 1, 10).pipe(
      map(page => {
        const asset = page.items.find(a => a.ref === entity);
        if (!asset) throw NOT_FOUND;
        return asset.id;
      }),
    );
  }
}
