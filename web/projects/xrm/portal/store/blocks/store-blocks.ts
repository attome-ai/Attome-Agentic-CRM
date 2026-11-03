import {
  ChangeDetectionStrategy, Component, Directive, computed, effect, inject, input, signal, untracked,
} from '@angular/core';
import { ActivatedRoute } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { PageContext } from '@attome/xrm/core/page-runtime';
import type { PageNode } from '@attome/xrm/core/page-runtime';
import { catchError, of } from 'rxjs';

import { CatalogueItem, GuestOrder, ShippingOption, ShopOrder, StoreService } from '../store.service';
import { StoreBasket, basketTotal, cents, fromCents, shownPrice } from './store-basket';

/** A product's name in the shopper's language. Pure. */
export function productName(item: Pick<CatalogueItem, 'name' | 'name_ar' | 'sku' | 'product_id'>, arabic: boolean): string {
  return (arabic && item.name_ar) || item.name || item.sku || item.product_id;
}

/** A six-digit code, spaces ignored. Pure. */
export function validCode(code: string): boolean {
  return /^\d{6}$/.test(code.replace(/\s+/g, ''));
}

/** What a guest's checkout still lacks before the order can be placed, as i18n keys. Pure. */
export function checkoutMissing(f: {
  code: string; name: string; address: string; country: string; rate: string | null;
}): string[] {
  const missing: string[] = [];
  if (!validCode(f.code)) missing.push('storeBlocks.needCode');
  if (!f.name.trim()) missing.push('storeBlocks.needName');
  if (!f.address.trim()) missing.push('storeBlocks.needAddress');
  if (!/^[A-Za-z]{2}$/.test(f.country.trim())) missing.push('storeBlocks.needCountry');
  if (!f.rate) missing.push('storeBlocks.needShipping');
  return missing;
}

const BLOCK_STYLES = `
  .sb { display: grid; gap: .75rem; }
  .sb-grid { display: grid; gap: .75rem; grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr)); margin: 0; padding: 0; list-style: none; }
  .sb-card { display: grid; gap: .375rem; border: 1px solid var(--color-border, #ddd); border-radius: 8px; padding: .75rem; }
  .sb-name { margin: 0; font-size: 1rem; }
  .sb-price { font-size: 1.125rem; font-weight: 700; margin: 0; }
  .sb-muted { color: var(--color-text-secondary, #666); margin: 0; font-size: .875rem; }
  .sb-badge { justify-self: start; border-radius: 999px; padding-block: .125rem; padding-inline: .5rem; font-size: .75rem; }
  .sb-badge-in_stock { background: var(--color-success-bg, #e6f4ea); }
  .sb-badge-low { background: var(--color-warning-bg, #fff4e5); }
  .sb-badge-sold_out { background: var(--color-danger-bg, #fde8e8); }
  .sb-row { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; }
  .sb-table { inline-size: 100%; border-collapse: collapse; }
  .sb-table th, .sb-table td { text-align: start; padding-block: .25rem; padding-inline: .5rem; border-block-end: 1px solid var(--color-border, #eee); }
  .sb-form { display: grid; gap: .5rem; max-inline-size: 32rem; }
  .sb-form button { justify-self: start; }
  .sb-qty { inline-size: 5rem; }
  .sb-error { color: var(--color-danger, #c53030); margin: 0; }
`;

/** The portal the page is on, and the shopper's basket in it. */
@Directive()
abstract class StoreBlockDirective {
  protected readonly ctx = inject(PageContext);
  protected readonly lang = inject(LangService);
  protected readonly store = inject(StoreService);
  protected readonly basket = inject(StoreBasket);

  readonly node = input.required<PageNode>();

  protected readonly keyword = computed(() => this.ctx.site());
  protected readonly arabic = computed(() => this.ctx.arabic());
  protected readonly dir = computed(() => (this.arabic() ? 'rtl' : 'ltr'));
  protected readonly error = signal<string | null>(null);

  constructor() {
    effect(() => {
      const keyword = this.keyword();
      if (keyword) untracked(() => this.basket.open(keyword));
    });
  }

  protected name(item: CatalogueItem): string {
    return productName(item, this.arabic());
  }

  protected money(amount: string, currency: string): string {
    const n = Number(amount);
    if (!Number.isFinite(n)) return `${amount} ${currency}`;
    try {
      return new Intl.NumberFormat(this.lang.intlLocale(), { style: 'currency', currency }).format(n);
    } catch {
      return `${n.toFixed(2)} ${currency}`;
    }
  }

  protected fail(e: ApiError): void {
    this.error.set(this.lang.errorText(e));
  }
}

/**
 * F8-T10 — `store.product_grid`: the products a guest may buy, each with
 * its price including VAT, the VAT in it, its stock badge, and an add to
 * the basket (not for a sold-out product). `props.search` narrows the list;
 * `props.detail_page` makes each name a link to that page with `?product=`.
 */
@Component({
  selector: 'xrm-store-product-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="sb" [attr.dir]="dir()" data-testid="store-product-grid">
      @if (error(); as e) { <p class="sb-error" role="alert">{{ e }}</p> }
      <ul class="sb-grid">
        @for (item of items(); track item.product_id) {
          <li class="sb-card" [attr.data-product]="item.product_id">
            @if (detailLink(item); as href) {
              <a [href]="href"><h3 class="sb-name" dir="auto">{{ name(item) }}</h3></a>
            } @else {
              <h3 class="sb-name" dir="auto">{{ name(item) }}</h3>
            }
            <p class="sb-price" data-price>{{ money(shown(item), item.currency) }}</p>
            @if (item.vat) {
              <p class="sb-muted">{{ 'storeBlocks.vatIncluded' | translate: { vat: money(item.vat, item.currency) } }}</p>
            }
            @if (item.stock) {
              <span [class]="'sb-badge sb-badge-' + item.stock" data-stock>{{ 'storeBlocks.stock.' + item.stock | translate }}</span>
            }
            <button type="button" [disabled]="item.stock === 'sold_out'" (click)="add(item)">{{ 'storeBlocks.add' | translate }}</button>
          </li>
        } @empty {
          <li class="sb-muted">{{ 'storeBlocks.noProducts' | translate }}</li>
        }
      </ul>
      @if (added()) { <p class="sb-muted" role="status">{{ 'storeBlocks.added' | translate }}</p> }
    </section>
  `,
  styles: [BLOCK_STYLES],
})
export class StoreProductGridComponent extends StoreBlockDirective {
  readonly items = signal<CatalogueItem[]>([]);
  readonly added = signal(false);
  protected readonly shown = shownPrice;

  constructor() {
    super();
    effect(() => {
      const keyword = this.keyword();
      const search = String(this.node().props?.['search'] ?? '');
      untracked(() => {
        if (keyword) this.store.guestCatalogue(keyword, search).subscribe({
          next: items => this.items.set(items),
          error: (e: ApiError) => this.fail(e),
        });
      });
    });
  }

  protected detailLink(item: CatalogueItem): string | null {
    const page = this.node().props?.['detail_page'];
    const keyword = this.keyword();
    if (typeof page !== 'string' || !/^[a-z0-9-]+$/.test(page) || !keyword) return null;
    return `/p/${encodeURIComponent(keyword)}/${page}?product=${encodeURIComponent(item.product_id)}`;
  }

  add(item: CatalogueItem): void {
    this.basket.add(item, this.name(item));
    this.added.set(true);
  }
}

/**
 * F8-T10 — `store.product_detail`: one product (`?product=` in the address,
 * else `props.product_id`) with its price including VAT and the VAT amount,
 * its stock badge, and a quantity to add to the basket.
 */
@Component({
  selector: 'xrm-store-product-detail',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="sb" [attr.dir]="dir()" data-testid="store-product-detail">
      @if (error(); as e) { <p class="sb-error" role="alert">{{ e }}</p> }
      @if (item(); as p) {
        <h2 class="sb-name" dir="auto">{{ name(p) }}</h2>
        @if (p.sku) { <p class="sb-muted" dir="ltr">{{ p.sku }}</p> }
        <p class="sb-price" data-price>{{ money(shown(p), p.currency) }}</p>
        @if (p.vat) {
          <p class="sb-muted" data-vat>{{ 'storeBlocks.priceBreakdown' | translate: { net: money(p.price, p.currency), vat: money(p.vat, p.currency) } }}</p>
        }
        @if (p.stock) {
          <span [class]="'sb-badge sb-badge-' + p.stock" data-stock>{{ 'storeBlocks.stock.' + p.stock | translate }}</span>
        }
        <div class="sb-row">
          <label for="sb-qty">{{ 'storeBlocks.quantity' | translate }}</label>
          <input id="sb-qty" class="sb-qty" type="number" min="1" step="1" [value]="quantity()"
                 (input)="quantity.set(+$any($event.target).value)" />
          <button type="button" [disabled]="p.stock === 'sold_out' || quantity() < 1" (click)="add(p)">{{ 'storeBlocks.add' | translate }}</button>
        </div>
        @if (added()) { <p class="sb-muted" role="status">{{ 'storeBlocks.added' | translate }}</p> }
      } @else if (missing()) {
        <p class="sb-muted">{{ 'storeBlocks.noProduct' | translate }}</p>
      }
    </section>
  `,
  styles: [BLOCK_STYLES],
})
export class StoreProductDetailComponent extends StoreBlockDirective {
  private readonly route = inject(ActivatedRoute, { optional: true });

  readonly item = signal<CatalogueItem | null>(null);
  readonly missing = signal(false);
  readonly quantity = signal(1);
  readonly added = signal(false);
  protected readonly shown = shownPrice;

  constructor() {
    super();
    effect(() => {
      const keyword = this.keyword();
      const fromProps = this.node().props?.['product_id'];
      const wanted = this.route?.snapshot.queryParamMap.get('product') ?? (typeof fromProps === 'string' ? fromProps : null);
      untracked(() => {
        if (!keyword || !wanted) {
          this.missing.set(!!keyword);
          return;
        }
        this.store.guestCatalogue(keyword).subscribe({
          next: items => {
            const found = items.find(i => i.product_id === wanted) ?? null;
            this.item.set(found);
            this.missing.set(!found);
          },
          error: (e: ApiError) => this.fail(e),
        });
      });
    });
  }

  add(item: CatalogueItem): void {
    this.basket.add(item, this.name(item), this.quantity());
    this.added.set(true);
  }
}

/** F8-T10 — `store.cart`: the guest's basket: quantities, removal and the total including VAT. */
@Component({
  selector: 'xrm-store-cart',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="sb" [attr.dir]="dir()" data-testid="store-cart">
      @if (basket.lines().length) {
        <table class="sb-table">
          <thead>
            <tr>
              <th scope="col">{{ 'storeBlocks.product' | translate }}</th>
              <th scope="col">{{ 'storeBlocks.quantity' | translate }}</th>
              <th scope="col">{{ 'storeBlocks.lineTotal' | translate }}</th>
              <th scope="col"><span class="sb-muted">{{ 'storeBlocks.remove' | translate }}</span></th>
            </tr>
          </thead>
          <tbody>
            @for (line of basket.lines(); track line.product_id) {
              <tr>
                <td dir="auto">{{ line.name }}</td>
                <td>
                  <input class="sb-qty" type="number" min="0" step="1" [value]="line.quantity"
                         [attr.aria-label]="'storeBlocks.quantityOf' | translate: { name: line.name }"
                         (change)="basket.set(line.product_id, +$any($event.target).value)" />
                </td>
                <td>{{ money(lineTotal(line.unit, line.quantity), line.currency) }}</td>
                <td>
                  <button type="button" [attr.aria-label]="'storeBlocks.removeOf' | translate: { name: line.name }"
                          (click)="basket.set(line.product_id, 0)">
                    <i class="las la-times" aria-hidden="true"></i>
                  </button>
                </td>
              </tr>
            }
          </tbody>
        </table>
        <p class="sb-price" data-total>{{ 'storeBlocks.totalWithVat' | translate: { total: money(total(), currency()) } }}</p>
      } @else {
        <p class="sb-muted">{{ 'storeBlocks.emptyBasket' | translate }}</p>
      }
    </section>
  `,
  styles: [BLOCK_STYLES],
})
export class StoreCartComponent extends StoreBlockDirective {
  protected readonly total = computed(() => basketTotal(this.basket.lines()));
  protected readonly currency = computed(() => this.basket.lines()[0]?.currency ?? 'SAR');

  protected lineTotal(unit: string, quantity: number): string {
    return fromCents(cents(unit) * quantity);
  }
}

type Step = 'phone' | 'details' | 'done';

/**
 * F8-T10 — `store.checkout`: a guest's checkout over F8-T7. The phone gets
 * a code for the basket's lines; with the code, the name and address, a
 * way to ship to it (F8-T7's shipping options) and cash on delivery or
 * paying online, the order is placed once (one key per checkout, so a
 * retry returns the same order). The order cannot be placed without the
 * code. The server prices everything again; the totals shown after are
 * the server's. Paying online opens the order's payment page, which offers
 * the methods the deployment's payment settings (F5) allow.
 */
@Component({
  selector: 'xrm-store-checkout',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="sb" [attr.dir]="dir()" data-testid="store-checkout">
      @if (error(); as e) { <p class="sb-error" role="alert">{{ e }}</p> }
      @switch (step()) {
        @case ('phone') {
          @if (basket.lines().length) {
            <form class="sb-form" (submit)="$event.preventDefault(); start()">
              <label for="sb-phone">{{ 'storeBlocks.phone' | translate }}</label>
              <input id="sb-phone" type="tel" dir="ltr" autocomplete="tel" [value]="phone()" (input)="phone.set($any($event.target).value)" />
              <button type="submit" [disabled]="busy() || !phone().trim()" data-send-code>{{ 'storeBlocks.sendCode' | translate }}</button>
            </form>
          } @else {
            <p class="sb-muted">{{ 'storeBlocks.emptyBasket' | translate }}</p>
          }
        }
        @case ('details') {
          <form class="sb-form" (submit)="$event.preventDefault(); place()">
            <p class="sb-muted">{{ 'storeBlocks.codeSent' | translate: { phone: phone() } }}</p>
            <label for="sb-code">{{ 'storeBlocks.code' | translate }}</label>
            <input id="sb-code" inputmode="numeric" autocomplete="one-time-code" dir="ltr" [value]="code()" (input)="code.set($any($event.target).value)" />
            <label for="sb-name">{{ 'storeBlocks.name' | translate }}</label>
            <input id="sb-name" dir="auto" autocomplete="name" [value]="fullName()" (input)="fullName.set($any($event.target).value)" />
            <label for="sb-address">{{ 'storeBlocks.address' | translate }}</label>
            <textarea id="sb-address" rows="2" dir="auto" autocomplete="street-address" [value]="address()" (input)="address.set($any($event.target).value)"></textarea>
            <label for="sb-city">{{ 'storeBlocks.city' | translate }}</label>
            <input id="sb-city" dir="auto" autocomplete="address-level2" [value]="city()" (change)="city.set($any($event.target).value); loadShipping()" />
            <label for="sb-country">{{ 'storeBlocks.country' | translate }}</label>
            <input id="sb-country" dir="ltr" maxlength="2" autocomplete="country" [value]="country()" (change)="country.set($any($event.target).value); loadShipping()" />
            <fieldset>
              <legend>{{ 'storeBlocks.shipping' | translate }}</legend>
              @for (o of options(); track o.rate_id) {
                <label class="sb-row">
                  <input type="radio" name="sb-rate" [checked]="rate() === o.rate_id" (change)="rate.set(o.rate_id)" />
                  <span dir="auto">{{ o.zone }} · {{ money(o.amount, currency()) }}</span>
                </label>
              } @empty {
                <p class="sb-muted">{{ 'storeBlocks.noShipping' | translate }}</p>
              }
            </fieldset>
            <fieldset>
              <legend>{{ 'storeBlocks.payment' | translate }}</legend>
              <label class="sb-row"><input type="radio" name="sb-pay" [checked]="!cod()" (change)="cod.set(false)" /> {{ 'storeBlocks.payOnline' | translate }}</label>
              <label class="sb-row"><input type="radio" name="sb-pay" [checked]="cod()" (change)="cod.set(true)" /> {{ 'storeBlocks.cashOnDelivery' | translate }}</label>
            </fieldset>
            @for (m of missing(); track m) { <p class="sb-muted" data-missing>{{ m | translate }}</p> }
            <button type="submit" [disabled]="busy() || missing().length > 0" data-place>{{ 'storeBlocks.place' | translate }}</button>
          </form>
        }
        @case ('done') {
          @if (order(); as o) {
            <div class="sb-form" role="status">
              <p>{{ 'storeBlocks.placed' | translate }}</p>
              <p class="sb-muted">{{ 'storeBlocks.vatLine' | translate: { vat: money(o.vat, currency()) } }}</p>
              <p class="sb-price" data-total>{{ 'storeBlocks.totalWithVat' | translate: { total: money(o.total, currency()) } }}</p>
              @if (o.payment_url) { <a [href]="o.payment_url" data-pay>{{ 'storeBlocks.payNow' | translate }}</a> }
            </div>
          }
        }
      }
    </section>
  `,
  styles: [BLOCK_STYLES],
})
export class StoreCheckoutComponent extends StoreBlockDirective {
  readonly step = signal<Step>('phone');
  readonly phone = signal('');
  readonly code = signal('');
  readonly fullName = signal('');
  readonly address = signal('');
  readonly city = signal('');
  readonly country = signal('SA');
  readonly rate = signal<string | null>(null);
  readonly cod = signal(false);
  readonly options = signal<ShippingOption[]>([]);
  readonly busy = signal(false);
  readonly order = signal<GuestOrder | null>(null);
  readonly missing = computed(() => checkoutMissing({
    code: this.code(), name: this.fullName(), address: this.address(), country: this.country(), rate: this.rate(),
  }));
  protected readonly currency = computed(() => this.basket.lines()[0]?.currency ?? 'SAR');
  private checkout: string | null = null;
  private key = '';

  start(): void {
    const keyword = this.keyword();
    if (!keyword || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    const lines = this.basket.lines().map(l => ({ product_id: l.product_id, quantity: String(l.quantity) }));
    this.store.guestStart(keyword, this.phone().trim(), lines).subscribe({
      next: started => {
        this.busy.set(false);
        this.checkout = started.checkout_id;
        this.key = `guest-${started.checkout_id}`;
        this.step.set('details');
        this.loadShipping();
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.fail(e);
      },
    });
  }

  loadShipping(): void {
    const keyword = this.keyword();
    if (!keyword || !/^[A-Za-z]{2}$/.test(this.country().trim())) return;
    this.store.shipping(keyword, this.country().trim().toUpperCase(), this.city(), basketTotal(this.basket.lines()))
      .pipe(catchError(() => of([] as ShippingOption[])))
      .subscribe(options => {
        this.options.set(options);
        if (!options.some(o => o.rate_id === this.rate())) this.rate.set(options[0]?.rate_id ?? null);
      });
  }

  place(): void {
    const keyword = this.keyword();
    const rate = this.rate();
    if (!keyword || !this.checkout || !rate || this.missing().length || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.store.guestConfirm(keyword, {
      checkout_id: this.checkout,
      code: this.code().replace(/\s+/g, ''),
      name: this.fullName().trim(),
      address: this.address().trim(),
      country: this.country().trim().toUpperCase(),
      city: this.city().trim() || null,
      shipping_rate_id: rate,
      cash_on_delivery: this.cod(),
    }, this.key).subscribe({
      next: order => {
        this.busy.set(false);
        this.order.set(order);
        this.basket.placed(order);
        this.step.set('done');
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(e.status === 401 ? this.lang.translate('storeBlocks.wrongCode') : this.lang.errorText(e));
      },
    });
  }
}

/**
 * F8-T10 — `store.order_status`: the order this tab placed as a guest, and,
 * for a signed-in member, their account's orders with each one's shipping
 * progress (F6-T15).
 */
@Component({
  selector: 'xrm-store-order-status',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  template: `
    <section class="sb" [attr.dir]="dir()" data-testid="store-order-status">
      @if (basket.lastOrder(); as o) {
        <div class="sb-card" data-guest-order>
          <p>{{ 'storeBlocks.lastOrder' | translate }}</p>
          <p class="sb-price">{{ o.total }}</p>
          @if (o.payment_url) { <a [href]="o.payment_url">{{ 'storeBlocks.payNow' | translate }}</a> }
        </div>
      }
      @if (orders().length) {
        <table class="sb-table">
          <thead>
            <tr>
              <th scope="col">{{ 'storeBlocks.order' | translate }}</th>
              <th scope="col">{{ 'storeBlocks.status' | translate }}</th>
              <th scope="col">{{ 'storeBlocks.lineTotal' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (o of orders(); track o.id) {
              <tr>
                <td dir="ltr">{{ o.order_number || o.name || o.id }}</td>
                <td>{{ o.status || '' }}</td>
                <td>{{ o.grand_total ? money(o.grand_total, o.currency || 'SAR') : '' }}</td>
              </tr>
            }
          </tbody>
        </table>
      } @else if (!basket.lastOrder()) {
        <p class="sb-muted">{{ (signedOut() ? 'storeBlocks.signInForOrders' : 'storeBlocks.noOrders') | translate }}</p>
      }
    </section>
  `,
  styles: [BLOCK_STYLES],
})
export class StoreOrderStatusComponent extends StoreBlockDirective {
  readonly orders = signal<ShopOrder[]>([]);
  readonly signedOut = signal(false);

  constructor() {
    super();
    effect(() => {
      const keyword = this.keyword();
      untracked(() => {
        if (keyword) this.store.orders(keyword).subscribe({
          next: orders => this.orders.set(orders),
          error: (e: ApiError) => {
            if (e.status === 401 || e.status === 404) this.signedOut.set(true);
            else this.fail(e);
          },
        });
      });
    });
  }
}
