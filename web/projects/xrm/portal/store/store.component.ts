import {
  ChangeDetectionStrategy, Component, effect, inject, input, signal, untracked,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { Observable, catchError, forkJoin, of } from 'rxjs';

import { Cart, CatalogueItem, CheckedOut, OrderLine, ShopOrder, StoreService } from './store.service';

type Tab = 'shop' | 'quick' | 'cart' | 'orders';

/** A quick-order line: `SKU quantity`, the quantity 1 when left out. */
export interface QuickLine {
  sku: string;
  quantity: number;
}

/** Quick-order text, one `SKU quantity` per line (spaces, tabs or a comma
 * between), blank lines skipped; `null` names the first bad line. Pure. */
export function parseQuickOrder(text: string): { lines: QuickLine[]; bad: string | null } {
  const lines: QuickLine[] = [];
  for (const raw of text.split('\n')) {
    const row = raw.trim();
    if (!row) continue;
    const [sku, qty] = row.split(/[\s,]+/);
    const quantity = qty === undefined ? 1 : Number(qty);
    if (!sku || !Number.isFinite(quantity) || quantity <= 0) return { lines: [], bad: row };
    lines.push({ sku, quantity });
  }
  return { lines, bad: null };
}

/**
 * F7-T2 — `/shop/:keyword`: one portal's shop for its signed-in members:
 * the products on sale to their account with its prices, a quick order by
 * SKU, the cart (change a quantity, remove, check out into an order, with a
 * note when it waits for approval) and the account's orders with each
 * one's lines and tracking. Everything goes through the portal's own shop
 * routes; the server decides the account and the prices.
 */
@Component({
  selector: 'xrm-portal-store',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, TranslatePipe],
  template: `
    <section class="ps" [attr.dir]="lang.isRtl() ? 'rtl' : 'ltr'" aria-labelledby="ps-title">
      <h1 id="ps-title">{{ 'portalStore.title' | translate }}</h1>
      @if (error(); as message) { <p class="ps-error" role="alert">{{ message }}</p> }
      @if (notice(); as n) { <p class="ps-notice" role="status" data-testid="ps-notice">{{ n | translate }}</p> }
      @if (signedOut()) {
        <p data-testid="ps-signed-out">{{ 'portalStore.signIn' | translate }}</p>
      } @else {
        <nav class="ps-tabs" [attr.aria-label]="'portalStore.title' | translate">
          @for (t of tabs; track t) {
            <button type="button" [class.ps-active]="tab() === t" [attr.data-testid]="'ps-tab-' + t"
                    (click)="setTab(t)">{{ 'portalStore.tab.' + t | translate }}</button>
          }
        </nav>

        @switch (tab()) {
          @case ('shop') {
            <form class="ps-search" (submit)="search($event)">
              <label for="ps-q">{{ 'portalStore.search' | translate }}</label>
              <input id="ps-q" data-testid="ps-search" [ngModel]="query()" (ngModelChange)="query.set($event)" name="q" />
              <button type="submit">{{ 'portalStore.searchButton' | translate }}</button>
            </form>
            @if (items().length) {
              <ul class="ps-items" data-testid="ps-items">
                @for (p of items(); track p.product_id) {
                  <li>
                    <span class="ps-name">{{ productName(p) }}</span>
                    @if (p.sku) { <span class="ps-sku" dir="ltr">{{ p.sku }}</span> }
                    <span class="ps-price" dir="ltr">{{ p.price }} {{ p.currency }}</span>
                    <button type="button" [attr.data-testid]="'ps-add-' + p.product_id" [disabled]="busy()"
                            (click)="add(p.product_id)">{{ 'portalStore.add' | translate }}</button>
                  </li>
                }
              </ul>
            } @else {
              <p class="ps-hint">{{ 'portalStore.noProducts' | translate }}</p>
            }
          }
          @case ('quick') {
            <form class="ps-quick" (submit)="quickOrder($event)">
              <label for="ps-quick">{{ 'portalStore.quickHint' | translate }}</label>
              <textarea id="ps-quick" dir="ltr" rows="6" data-testid="ps-quick" name="quick"
                        [ngModel]="quickText()" (ngModelChange)="quickText.set($event)"></textarea>
              <button type="submit" [disabled]="busy() || !quickText().trim()">{{ 'portalStore.addAll' | translate }}</button>
            </form>
          }
          @case ('cart') {
            @if (cart(); as c) {
              @if (c.lines.length) {
                <table class="ps-table" data-testid="ps-cart">
                  <thead><tr>
                    <th scope="col">{{ 'portalStore.product' | translate }}</th>
                    <th scope="col">{{ 'portalStore.quantity' | translate }}</th>
                    <th scope="col">{{ 'portalStore.lineTotal' | translate }}</th>
                    <th scope="col"><span class="ps-visually-hidden">{{ 'portalStore.remove' | translate }}</span></th>
                  </tr></thead>
                  <tbody>
                    @for (l of c.lines; track l.product_id) {
                      <tr>
                        <td>{{ l.name || l.product_id }}
                          @if (!l.unit_price) { <span class="ps-off">{{ 'portalStore.offSale' | translate }}</span> }
                        </td>
                        <td><input type="number" min="0" step="1" class="ps-qty" [value]="l.quantity"
                                   [attr.aria-label]="'portalStore.quantity' | translate"
                                   (change)="setQuantity(l.product_id, $event)" /></td>
                        <td dir="ltr">{{ l.line_total ?? '–' }}</td>
                        <td><button type="button" [attr.data-testid]="'ps-remove-' + l.product_id"
                                    (click)="update(l.product_id, 0)">{{ 'portalStore.remove' | translate }}</button></td>
                      </tr>
                    }
                  </tbody>
                </table>
                <p class="ps-total">{{ 'portalStore.total' | translate }} <span dir="ltr">{{ c.total }} {{ c.currency }}</span></p>
                <button type="button" data-testid="ps-checkout" [disabled]="busy() || !c.can_check_out"
                        (click)="checkout()">{{ 'portalStore.checkout' | translate }}</button>
              } @else {
                <p class="ps-hint">{{ 'portalStore.emptyCart' | translate }}</p>
              }
            }
          }
          @case ('orders') {
            @if (orders().length) {
              <ul class="ps-orders" data-testid="ps-orders">
                @for (o of orders(); track o.id) {
                  <li>
                    <button type="button" class="ps-order" (click)="openOrder(o.id)">
                      <span dir="ltr">{{ o.order_number || o.name }}</span>
                      <span>{{ 'portalStore.status.' + (o.status || 'draft') | translate }}</span>
                      <span dir="ltr">{{ o.grand_total }} {{ o.currency }}</span>
                    </button>
                    @if (openOrderId() === o.id) {
                      <ul class="ps-lines" data-testid="ps-order-lines">
                        @for (l of orderLines(); track l.line_id) {
                          <li>
                            {{ 'portalStore.lineProgress' | translate: { shipped: l.shipped, ordered: l.ordered } }}
                            @for (s of l.shipments; track s.shipment_id) {
                              <span class="ps-tracking" dir="ltr">{{ s.carrier }} {{ s.tracking_number }}</span>
                            }
                          </li>
                        } @empty {
                          <li class="ps-hint">{{ 'portalStore.notShipped' | translate }}</li>
                        }
                      </ul>
                    }
                  </li>
                }
              </ul>
            } @else {
              <p class="ps-hint">{{ 'portalStore.noOrders' | translate }}</p>
            }
          }
        }
      }
    </section>
  `,
  styles: [`
    .ps { display: grid; gap: var(--space-4, 1rem); max-inline-size: 60rem; margin-inline: auto; padding-inline: 1rem; }
    .ps-tabs { display: flex; flex-wrap: wrap; gap: .5rem; }
    .ps-tabs .ps-active { font-weight: 600; text-decoration: underline; }
    .ps-search, .ps-quick { display: flex; flex-wrap: wrap; gap: .5rem; align-items: end; }
    .ps-quick { flex-direction: column; align-items: stretch; }
    .ps-items, .ps-orders, .ps-lines { list-style: none; margin: 0; padding: 0; display: grid; gap: .5rem; }
    .ps-items li { display: flex; flex-wrap: wrap; gap: .75rem; align-items: center; border-block-end: 1px solid var(--color-border); padding-block: .5rem; }
    .ps-name { flex: 1 1 12rem; }
    .ps-sku, .ps-hint, .ps-off { color: var(--color-text-secondary); }
    .ps-table { inline-size: 100%; border-collapse: collapse; }
    .ps-table th, .ps-table td { text-align: start; padding-block: .25rem; padding-inline: .5rem; border-block-end: 1px solid var(--color-border); }
    .ps-qty { inline-size: 5rem; }
    .ps-order { display: flex; flex-wrap: wrap; gap: 1rem; inline-size: 100%; text-align: start; }
    .ps-tracking { margin-inline-start: .5rem; }
    .ps-error { color: var(--color-danger); }
    .ps-visually-hidden { position: absolute; inline-size: 1px; block-size: 1px; overflow: hidden; clip-path: inset(50%); }
  `],
})
export class StoreComponent {
  private readonly svc = inject(StoreService);
  protected readonly lang = inject(LangService);
  protected readonly tabs: Tab[] = ['shop', 'quick', 'cart', 'orders'];

  /** The portal's keyword (route parameter). */
  readonly keyword = input.required<string>();

  readonly tab = signal<Tab>('shop');
  readonly query = signal('');
  readonly items = signal<CatalogueItem[]>([]);
  readonly cart = signal<Cart | null>(null);
  readonly orders = signal<ShopOrder[]>([]);
  readonly openOrderId = signal<string | null>(null);
  readonly orderLines = signal<OrderLine[]>([]);
  readonly quickText = signal('');
  readonly busy = signal(false);
  readonly signedOut = signal(false);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);

  constructor() {
    effect(() => {
      const keyword = this.keyword();
      untracked(() => this.loadCatalogue(keyword));
    });
  }

  protected productName(p: CatalogueItem): string {
    return (this.lang.isRtl() && p.name_ar) || p.name || p.sku || p.product_id;
  }

  setTab(tab: Tab): void {
    this.tab.set(tab);
    this.notice.set(null);
    if (tab === 'cart') this.loadCart();
    if (tab === 'orders') this.loadOrders();
  }

  search(event: Event): void {
    event.preventDefault();
    this.loadCatalogue(this.keyword());
  }

  add(product: string): void {
    const current = this.cart()?.lines.find(l => l.product_id === product);
    this.update(product, (current ? Number(current.quantity) : 0) + 1, 'portalStore.added');
  }

  protected setQuantity(product: string, event: Event): void {
    const quantity = Number((event.target as HTMLInputElement).value);
    if (Number.isFinite(quantity) && quantity >= 0) this.update(product, quantity);
  }

  update(product: string, quantity: number, notice?: string): void {
    this.busy.set(true);
    this.guard(this.svc.setLine(this.keyword(), product, quantity)).subscribe(cart => {
      this.busy.set(false);
      if (!cart) return;
      this.cart.set(cart);
      if (notice) this.notice.set(notice);
    });
  }

  /** Adds every `SKU quantity` line whose SKU is on sale; the rest are named. */
  quickOrder(event: Event): void {
    event.preventDefault();
    const { lines, bad } = parseQuickOrder(this.quickText());
    if (bad !== null) {
      this.error.set(this.lang.translate('portalStore.badLine', { line: bad }));
      return;
    }
    if (!lines.length) return;
    this.busy.set(true);
    const keyword = this.keyword();
    forkJoin(lines.map(l => this.guard(this.svc.catalogue(keyword, l.sku)))).subscribe(found => {
      const matches = lines.map((l, i) => ({
        line: l,
        item: (found[i] ?? []).find(p => (p.sku ?? '').toLowerCase() === l.sku.toLowerCase()),
      }));
      const missing = matches.filter(m => !m.item).map(m => m.line.sku);
      const adds = matches.flatMap(m =>
        m.item ? [this.guard(this.svc.setLine(keyword, m.item.product_id, m.line.quantity))] : []);
      const done = (carts: (Cart | null)[]) => {
        this.busy.set(false);
        const last = carts.filter((c): c is Cart => c !== null).pop();
        if (last) this.cart.set(last);
        if (missing.length) this.error.set(this.lang.translate('portalStore.notFound', { skus: missing.join(', ') }));
        else this.notice.set('portalStore.added');
        if (!missing.length) this.quickText.set('');
      };
      if (!adds.length) {
        done([]);
        return;
      }
      forkJoin(adds).subscribe(done);
    });
  }

  checkout(): void {
    this.busy.set(true);
    this.guard(this.svc.checkout(this.keyword())).subscribe((done: CheckedOut | null) => {
      this.busy.set(false);
      if (!done) return;
      this.cart.set(null);
      this.setTab('orders');
      this.notice.set(done.needs_approval ? 'portalStore.orderedNeedsApproval' : 'portalStore.ordered');
    });
  }

  openOrder(id: string): void {
    if (this.openOrderId() === id) {
      this.openOrderId.set(null);
      return;
    }
    this.openOrderId.set(id);
    this.orderLines.set([]);
    this.svc.orderLines(this.keyword(), id).pipe(catchError(() => of(null))).subscribe(order => {
      this.orderLines.set(order?.lines ?? []);
    });
  }

  private loadCatalogue(keyword: string): void {
    this.guard(this.svc.catalogue(keyword, this.query())).subscribe(items => this.items.set(items ?? []));
    this.guard(this.svc.cart(keyword)).subscribe(cart => cart && this.cart.set(cart));
  }

  private loadCart(): void {
    this.guard(this.svc.cart(this.keyword())).subscribe(cart => cart && this.cart.set(cart));
  }

  private loadOrders(): void {
    this.guard(this.svc.orders(this.keyword())).subscribe(orders => this.orders.set(orders ?? []));
  }

  private guard<T>(call: Observable<T>): Observable<T | null> {
    return call.pipe(
      catchError((e: unknown) => {
        this.busy.set(false);
        if ((e as ApiError).status === 401) this.signedOut.set(true);
        else this.error.set(this.lang.errorText(e as ApiError));
        return of(null);
      }),
    );
  }
}
