import { DOCUMENT } from '@angular/common';
import {
  ChangeDetectionStrategy, Component, ElementRef, OnInit, computed, inject, input, signal, viewChild,
} from '@angular/core';
import { ApiService, LangService, TranslatePipe } from '@attome/base';

/** `GET /api/v1/pay/{token}`: what the payer is asked to pay. */
export interface PayView {
  amount: string;
  currency: string;
  invoice_number: string | null;
  seller_name: string | null;
  locale: string;
  expires_at: string;
}

/** A gateway's embeddable payment form (HyperPay). */
export interface CheckoutWidget {
  script_url: string;
  integrity: string | null;
  brands: string;
}

/** `POST /api/v1/pay/{token}/checkout`. */
export interface CheckoutStarted {
  payment_id: string;
  redirect_url: string | null;
  widget: CheckoutWidget | null;
}

/** Currencies with three decimals (ISO 4217), as the server rounds them. */
const THREE_DECIMALS = new Set(['KWD', 'BHD', 'OMR', 'JOD', 'IQD', 'LYD', 'TND']);

/** An amount (decimal text) for `locale`, with the currency's decimals. */
export function formatPayAmount(amount: string, currency: string, locale: string): string {
  const value = Number(amount);
  if (!Number.isFinite(value)) return `${amount} ${currency}`;
  const digits = THREE_DECIMALS.has(currency.toUpperCase()) ? 3 : 2;
  return new Intl.NumberFormat(locale, {
    style: 'currency', currency, minimumFractionDigits: digits, maximumFractionDigits: digits,
  }).format(value);
}

type Stage = 'loading' | 'ready' | 'starting' | 'widget' | 'missing' | 'failed';

/**
 * The hosted payment page (roadmap F5-T15) at `/pay/:token`: public, no
 * session. It shows only what the link's public endpoint returns (amount,
 * invoice number, seller) and, on Pay, starts the gateway's checkout: the
 * payer is sent to the gateway's own page, or the gateway's form is
 * embedded here (HyperPay). Card details are only ever typed on the
 * gateway's page or form, never into an Attome field.
 *
 * Its language starts from the link's (the payer's browser) with a toggle;
 * the page takes the language's direction, and logical CSS only.
 */
@Component({
  selector: 'app-pay-page',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <main class="pay" [attr.dir]="dir()" [attr.lang]="lang.current()">
      <section class="pay-card" aria-labelledby="pay-title">
        <div class="pay-head">
          <h1 id="pay-title">{{ 'pay.title' | translate }}</h1>
          <button type="button" class="pay-lang" (click)="toggleLanguage()">
            {{ 'pay.otherLanguage' | translate }}
          </button>
        </div>
        @switch (stage()) {
          @case ('loading') { <p class="pay-muted" role="status">{{ 'pay.loading' | translate }}</p> }
          @case ('missing') { <p class="pay-error" role="alert">{{ 'pay.notFound' | translate }}</p> }
          @default {
            @if (view(); as v) {
              <dl class="pay-facts">
                @if (v.seller_name) {
                  <div><dt>{{ 'pay.seller' | translate }}</dt><dd><bdi>{{ v.seller_name }}</bdi></dd></div>
                }
                @if (v.invoice_number) {
                  <div><dt>{{ 'pay.invoice' | translate }}</dt><dd><bdi>{{ v.invoice_number }}</bdi></dd></div>
                }
                <div class="pay-amount">
                  <dt>{{ 'pay.amount' | translate }}</dt>
                  <dd class="num">{{ amount() }}</dd>
                </div>
              </dl>
              @if (stage() === 'failed') {
                <p class="pay-error" role="alert">{{ 'pay.failed' | translate }}</p>
              }
              @if (stage() !== 'widget') {
                <button type="button" class="pay-button" [disabled]="stage() === 'starting'" (click)="pay()">
                  {{ (stage() === 'starting' ? 'pay.starting' : 'pay.pay') | translate }}
                </button>
                <p class="pay-muted">{{ 'pay.secure' | translate }}</p>
              }
            }
          }
        }
        <div #widgetHost class="pay-widget"></div>
      </section>
    </main>
  `,
  styles: [`
    :host { display: block; min-block-size: 100vh; background: var(--color-bg-secondary, #f6f7f9); }
    .pay { display: flex; justify-content: center; padding-block: 3rem; padding-inline: 1rem; }
    .pay-card { inline-size: 100%; max-inline-size: 28rem; background: var(--color-bg, #fff);
      border: 1px solid var(--color-border, #e3e5e8); border-radius: 0.75rem;
      padding-block: 1.5rem; padding-inline: 1.5rem; display: flex; flex-direction: column; gap: 1rem; }
    .pay-head { display: flex; justify-content: space-between; align-items: center; gap: 1rem; }
    .pay-head h1 { margin-block: 0; font-size: 1.25rem; }
    .pay-lang { background: none; border: none; color: var(--color-accent, #2563eb); cursor: pointer; }
    .pay-facts { margin-block: 0; display: flex; flex-direction: column; gap: 0.5rem; }
    .pay-facts div { display: flex; justify-content: space-between; gap: 1rem; }
    .pay-facts dt { color: var(--color-text-secondary, #5b616b); }
    .pay-facts dd { margin-inline-start: 0; text-align: end; }
    .pay-amount dd { font-size: 1.5rem; font-weight: 600; }
    .num { font-variant-numeric: tabular-nums; unicode-bidi: isolate; }
    .pay-button { padding-block: 0.75rem; padding-inline: 1rem; border: none; border-radius: 0.5rem;
      background: var(--color-accent, #2563eb); color: var(--color-on-accent, #fff); font-size: 1rem; cursor: pointer; }
    .pay-button[disabled] { opacity: 0.6; cursor: progress; }
    .pay-muted { margin-block: 0; color: var(--color-text-secondary, #5b616b); font-size: 0.8125rem; }
    .pay-error { margin-block: 0; color: var(--color-danger, #b42318); }
  `],
})
export class PayPageComponent implements OnInit {
  private readonly api = inject(ApiService);
  protected readonly lang = inject(LangService);
  private readonly doc = inject(DOCUMENT);

  /** The link's `{public_id}.{secret}`, from the route. */
  readonly token = input.required<string>();

  readonly stage = signal<Stage>('loading');
  readonly view = signal<PayView | null>(null);
  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));
  readonly amount = computed(() => {
    const v = this.view();
    return v ? formatPayAmount(v.amount, v.currency, this.lang.intlLocale()) : '';
  });

  private readonly widgetHost = viewChild<ElementRef<HTMLElement>>('widgetHost');

  ngOnInit(): void {
    this.api.get<PayView>(`/api/v1/pay/${encodeURIComponent(this.token())}`).subscribe({
      next: view => {
        this.view.set(view);
        if (view.locale && view.locale !== this.lang.current()) {
          void this.lang.set(view.locale);
        }
        this.stage.set('ready');
      },
      // Every miss is the same 404: the link is unknown, wrong, expired, used
      // or cancelled, and the page never says which.
      error: () => this.stage.set('missing'),
    });
  }

  toggleLanguage(): void {
    void this.lang.toggle();
  }

  pay(): void {
    this.stage.set('starting');
    this.api.post<CheckoutStarted>(`/api/v1/pay/${encodeURIComponent(this.token())}/checkout`, {}).subscribe({
      next: started => {
        if (started.redirect_url) {
          this.doc.location.assign(started.redirect_url);
        } else if (started.widget) {
          this.mountWidget(started.widget);
        } else {
          this.stage.set('failed');
        }
      },
      error: () => this.stage.set('failed'),
    });
  }

  /** The gateway's form and script, the card fields being the gateway's. */
  private mountWidget(widget: CheckoutWidget): void {
    const host = this.widgetHost()?.nativeElement;
    if (!host || !widget.script_url.startsWith('https://')) {
      this.stage.set('failed');
      return;
    }
    const form = this.doc.createElement('form');
    form.action = `${this.doc.location.origin}/pay/return`;
    form.className = 'paymentWidgets';
    form.setAttribute('data-brands', widget.brands);
    const script = this.doc.createElement('script');
    script.src = widget.script_url;
    if (widget.integrity) {
      script.integrity = widget.integrity;
      script.crossOrigin = 'anonymous';
    }
    host.replaceChildren(form, script);
    this.stage.set('widget');
  }
}
