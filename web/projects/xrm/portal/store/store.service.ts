import { Injectable, inject } from '@angular/core';
import { SdkService } from '@attome/base';
import { Observable } from 'rxjs';

/** A product on sale, priced for the account (`attome_sales::commerce::CatalogueItem`). */
export interface CatalogueItem {
  product_id: string;
  name?: string | null;
  name_ar?: string | null;
  sku?: string | null;
  price: string;
  currency: string;
  /** F8-T10: the VAT on one and the price with it (absent before the API regeneration). */
  vat?: string;
  price_with_vat?: string;
  /** F8-T10: free stock at the shop's location; absent when not tracked. */
  stock?: StockBadge | null;
}

export type StockBadge = 'in_stock' | 'low' | 'sold_out';

/** A way to ship (`attome_sales::shipping::ShippingOption`). */
export interface ShippingOption {
  rate_id: string;
  zone: string;
  method: string;
  amount: string;
  cod_fee: string;
}

/** A started guest checkout: a code was texted to the phone. */
export interface GuestStarted {
  checkout_id: string;
  expires_at: string;
}

/** What a guest confirms (`attome_sales::guest_checkout::Confirm`). */
export interface GuestConfirm {
  checkout_id: string;
  code: string;
  name: string;
  address: string;
  country: string;
  city?: string | null;
  shipping_rate_id: string;
  cash_on_delivery: boolean;
  coupon?: string | null;
}

/** The order a guest placed. */
export interface GuestOrder {
  order_id: string;
  subtotal: string;
  discount_total: string;
  shipping: string;
  vat: string;
  total: string;
  payment_url?: string | null;
}

export interface CartLine {
  product_id: string;
  name?: string | null;
  quantity: string;
  unit_price?: string | null;
  line_total?: string | null;
}

export interface Cart {
  cart_id?: string | null;
  currency: string;
  lines: CartLine[];
  total: string;
  can_check_out: boolean;
}

export interface CheckedOut {
  order_id: string;
  total: string;
  needs_approval: boolean;
  approval_id?: string | null;
}

export interface ShopOrder {
  id: string;
  name?: string | null;
  order_number?: string | null;
  status?: string | null;
  currency?: string | null;
  grand_total?: string | null;
  ordered_on?: string | null;
}

/** An order's line as the where-is-my-order route answers it (F6-T15). */
export interface OrderLine {
  line_id: string;
  ordered: number;
  shipped: number;
  delivered: number;
  status?: string | null;
  shipments: { shipment_id: string; carrier?: string | null; tracking_number?: string | null; status?: string | null }[];
}

/**
 * F7-T2: one portal's shop routes (`/{keyword}/api/v1/shop/...`, F7-T1) and
 * its order tracking (`/{keyword}/api/v1/fulfilment/orders/{id}`, F6-T15),
 * under the portal user's own session. The account is the server's choice,
 * never sent from here.
 */
@Injectable({ providedIn: 'root' })
export class StoreService {
  private readonly sdk = inject(SdkService);

  private base(keyword: string): string {
    return `/${encodeURIComponent(keyword)}/api/v1`;
  }

  catalogue(keyword: string, search: string): Observable<CatalogueItem[]> {
    const query = search.trim() ? { search: search.trim() } : undefined;
    return this.sdk.get<CatalogueItem[]>(`${this.base(keyword)}/shop/catalogue`, { query });
  }

  /** F8-T10: the catalogue a guest sees, with VAT and stock badges. */
  guestCatalogue(keyword: string, search = ''): Observable<CatalogueItem[]> {
    const query = search.trim() ? { search: search.trim() } : undefined;
    return this.sdk.get<CatalogueItem[]>(`${this.base(keyword)}/shop/guest/catalogue`, { query });
  }

  shipping(keyword: string, country: string, city: string, total: string): Observable<ShippingOption[]> {
    return this.sdk.get<ShippingOption[]>(`${this.base(keyword)}/shop/shipping`, {
      query: { country, city: city.trim() || undefined, total },
    });
  }

  /** F8-T7: texts a code to `phone` for these lines. */
  guestStart(keyword: string, phone: string, lines: { product_id: string; quantity: string }[]): Observable<GuestStarted> {
    return this.sdk.post<GuestStarted>(`${this.base(keyword)}/shop/guest/start`, { body: { phone, lines } });
  }

  /** F8-T7: places the order; the same `key` returns the same order again. */
  guestConfirm(keyword: string, body: GuestConfirm, key: string): Observable<GuestOrder> {
    return this.sdk.post<GuestOrder>(`${this.base(keyword)}/shop/guest/confirm`, { body, idempotencyKey: key });
  }

  cart(keyword: string): Observable<Cart> {
    return this.sdk.get<Cart>(`${this.base(keyword)}/shop/cart`);
  }

  setLine(keyword: string, product: string, quantity: number): Observable<Cart> {
    return this.sdk.put<Cart>(`${this.base(keyword)}/shop/cart/lines/${encodeURIComponent(product)}`, {
      body: { quantity: String(quantity) },
    });
  }

  checkout(keyword: string): Observable<CheckedOut> {
    return this.sdk.post<CheckedOut>(`${this.base(keyword)}/shop/cart/checkout`, { body: {} });
  }

  orders(keyword: string): Observable<ShopOrder[]> {
    return this.sdk.get<ShopOrder[]>(`${this.base(keyword)}/shop/orders`);
  }

  orderLines(keyword: string, order: string): Observable<{ order_id: string; lines: OrderLine[] }> {
    return this.sdk.get<{ order_id: string; lines: OrderLine[] }>(
      `${this.base(keyword)}/fulfilment/orders/${encodeURIComponent(order)}`);
  }
}
