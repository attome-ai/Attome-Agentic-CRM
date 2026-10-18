import { ChangeDetectionStrategy, Component, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiError, ApiService, TranslatePipe } from '@attome/base';

/** One message in ZATCA's validation results. */
export interface ZatcaMessage {
  type?: string | null;
  code?: string | null;
  category?: string | null;
  message?: string | null;
  status?: string | null;
}

/** `attome_einvoice::document::DocumentState`. */
export interface EinvoiceDocument {
  id: string;
  invoice_id: string;
  profile: 'standard' | 'simplified' | string;
  status: 'pending' | 'cleared' | 'reported' | 'rejected' | 'failed' | string;
  icv: number;
  invoice_hash: string;
  qr: string;
  attempts: number;
  validation: {
    infoMessages?: ZatcaMessage[];
    warningMessages?: ZatcaMessage[];
    errorMessages?: ZatcaMessage[];
    status?: string | null;
  } | null;
  last_error: string | null;
}

/** ZATCA's errors then warnings, as one list to show. */
export function zatcaMessages(doc: EinvoiceDocument): ZatcaMessage[] {
  return [...(doc.validation?.errorMessages ?? []), ...(doc.validation?.warningMessages ?? [])];
}

/**
 * An invoice's e-invoice compliance (roadmap AG2-T4): cleared, reported,
 * waiting or rejected, with ZATCA's errors and warnings and when it was
 * last tried. Hidden for an invoice that has no e-invoice (the route answers
 * 404), so a deployment without e-invoicing never sees it. Its own entry
 * point so the invoice form loads it only when it opens.
 */
@Component({
  selector: 'xrm-einvoice-status',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    @if (document(); as doc) {
      <section class="eis" aria-labelledby="eis-title" [attr.data-status]="doc.status">
        <h3 id="eis-title">{{ 'einvoiceStatus.title' | translate }}</h3>
        <p>
          <strong>{{ 'einvoiceStatus.status.' + doc.status | translate }}</strong>
          <small>{{ 'einvoiceStatus.profile.' + doc.profile | translate }}</small>
          <small>{{ 'einvoiceStatus.counter' | translate: { icv: doc.icv } }}</small>
        </p>
        @if (doc.status === 'pending' && doc.last_error) {
          <p class="eis-muted">{{ 'einvoiceStatus.retrying' | translate: { attempts: doc.attempts } }} {{ doc.last_error }}</p>
        }
        @if (messages().length) {
          <ul class="eis-messages">
            @for (m of messages(); track $index) {
              <li [attr.data-kind]="m.type"><code>{{ m.code }}</code> {{ m.message }}</li>
            }
          </ul>
        }
      </section>
    }
  `,
  styles: [`
    :host { display: block; }
    .eis { display: flex; flex-direction: column; gap: 0.375rem; padding-block: 0.75rem;
      border-block-start: 1px solid var(--color-border); }
    .eis h3 { margin-block: 0; font-size: 1rem; }
    .eis p { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: baseline; margin-block: 0; }
    .eis[data-status="rejected"] strong { color: var(--color-danger); }
    .eis[data-status="cleared"] strong, .eis[data-status="reported"] strong { color: var(--color-success); }
    .eis-messages { margin-block: 0; padding-inline-start: 1.25rem; }
    .eis-messages li[data-kind="ERROR"] { color: var(--color-danger); }
    .eis-muted { color: var(--color-text-secondary); font-size: 0.8125rem; }
  `],
})
export class EinvoiceStatusComponent {
  private readonly api = inject(ApiService);

  /** The invoice; empty for a new record. */
  readonly invoiceId = input<string | null>(null);

  readonly document = signal<EinvoiceDocument | null>(null);
  readonly messages = signal<ZatcaMessage[]>([]);

  constructor() {
    effect(() => {
      const id = this.invoiceId();
      untracked(() => this.load(id));
    });
  }

  load(id: string | null): void {
    if (!id) {
      this.document.set(null);
      return;
    }
    this.api.get<EinvoiceDocument>(`/api/v1/billing/invoices/${encodeURIComponent(id)}/einvoice`).subscribe({
      next: doc => {
        this.document.set(doc);
        this.messages.set(zatcaMessages(doc));
      },
      // No e-invoice (404) or no access: nothing to show.
      error: (_: ApiError) => this.document.set(null),
    });
  }
}
