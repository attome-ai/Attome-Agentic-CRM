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
