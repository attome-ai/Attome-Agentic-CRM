import { Injectable, signal } from '@angular/core';

import type { CatalogueItem, GuestOrder } from '../store.service';

/** One basket line: a product, how many, and its price with VAT for one. */
export interface BasketLine {
  product_id: string;
  name: string;
  quantity: number;
  /** A decimal in text. */
  unit: string;
  currency: string;
}

/** A decimal in text, in cents; 0 when it is not a number. Pure. */
export function cents(value: string | null | undefined): number {
  const n = Number(value ?? '');
  return Number.isFinite(n) ? Math.round(n * 100) : 0;
}

/** Cents as a decimal with two places. Pure. */
export function fromCents(value: number): string {
  return (value / 100).toFixed(2);
}

/** The basket's total with VAT, to the cent. Pure. */
export function basketTotal(lines: readonly BasketLine[]): string {
  return fromCents(lines.reduce((sum, l) => sum + cents(l.unit) * l.quantity, 0));
}

/** The price a shopper sees for one: with VAT when the API gives it. Pure. */
export function shownPrice(item: CatalogueItem): string {
  return item.price_with_vat ?? item.price;
}

/**
 * F8-T10: a guest's basket in one portal, shared by the store blocks of a
 * page (the grid and the detail add to it, the cart and the checkout read
 * it) and kept for the browser tab in session storage. It holds products
 * and quantities with the price last shown; the server prices the order
 * again at checkout and never takes a price from here.
 */
@Injectable({ providedIn: 'root' })
export class StoreBasket {
  readonly lines = signal<readonly BasketLine[]>([]);
  /** The order placed last in this tab, for the order status block. */
  readonly lastOrder = signal<GuestOrder | null>(null);
  private keyword: string | null = null;

  /** Switches to `keyword`'s basket, reading it back from the tab's storage. */
  open(keyword: string): void {
    if (this.keyword === keyword) return;
    this.keyword = keyword;
    const saved = this.read(`attome-store:${keyword}:basket`);
    this.lines.set(Array.isArray(saved) ? (saved as BasketLine[]) : []);
    this.lastOrder.set(this.read(`attome-store:${keyword}:order`) as GuestOrder | null);
  }

  add(item: CatalogueItem, name: string, quantity = 1): void {
    const current = this.lines().find(l => l.product_id === item.product_id);
    this.set(item.product_id, (current?.quantity ?? 0) + quantity, {
      product_id: item.product_id, name, quantity: 0, unit: shownPrice(item), currency: item.currency,
    });
  }

  /** Sets a line's quantity; 0 removes it. */
  set(product: string, quantity: number, line?: BasketLine): void {
    const q = Number.isFinite(quantity) ? Math.max(0, Math.floor(quantity)) : 0;
    const existing = this.lines().some(l => l.product_id === product);
    if (q === 0) this.lines.update(list => list.filter(l => l.product_id !== product));
    else if (existing) this.lines.update(list => list.map(l => (l.product_id === product ? { ...l, quantity: q } : l)));
    else if (line) this.lines.update(list => [...list, { ...line, quantity: q }]);
    this.save();
  }

  placed(order: GuestOrder): void {
    this.lines.set([]);
    this.lastOrder.set(order);
    this.save();
  }

  private save(): void {
    if (!this.keyword) return;
    try {
      sessionStorage.setItem(`attome-store:${this.keyword}:basket`, JSON.stringify(this.lines()));
      sessionStorage.setItem(`attome-store:${this.keyword}:order`, JSON.stringify(this.lastOrder()));
    } catch {
      // Storage off (private window): the basket lasts for the page only.
    }
  }

  private read(key: string): unknown {
    try {
      const raw = sessionStorage.getItem(key);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  }
}
