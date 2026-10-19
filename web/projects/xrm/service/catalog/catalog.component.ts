import { ChangeDetectionStrategy, Component, DestroyRef, OnInit, computed, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { ApiError, AuthService, TranslatePipe } from '@attome/base';
import { Subject, catchError, debounceTime, distinctUntilChanged, of, switchMap } from 'rxjs';

import {
  CartLine,
  CatalogOffering,
  OrderRecipient,
  OrderView,
  ServiceAdminService,
  itemCancellable,
} from '../services/service-admin.service';

/**
 * G3-T3: the service catalog. Search offerings in Arabic or English (the
 * server folds letter forms and keeps to active offerings), add them to a
 * cart, order for yourself or someone else, and follow your orders item by
 * item, cancelling one that has not finished.
 */
@Component({
  selector: 'attome-service-catalog',
  standalone: true,
  imports: [TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['../../styles/admin-page.css', './catalog.component.css'],
  templateUrl: './catalog.component.html',
})
export class CatalogComponent implements OnInit {
  private readonly svc = inject(ServiceAdminService);
  private readonly auth = inject(AuthService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly typed = new Subject<string>();

  readonly offerings = signal<CatalogOffering[]>([]);
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly cart = signal<CartLine[]>([]);
  readonly recipients = signal<OrderRecipient[]>([]);
  /** Who the order is for; empty means the person ordering. */
  readonly recipientId = signal('');
  readonly placing = signal(false);
  readonly placedReference = signal<string | null>(null);
  readonly orders = signal<OrderView[]>([]);

  readonly cartCount = computed(() => this.cart().reduce((n, l) => n + l.quantity, 0));
  readonly canCancel = itemCancellable;

  ngOnInit(): void {
    this.typed
      .pipe(
        debounceTime(300),
        distinctUntilChanged(),
        switchMap(q => {
          this.loading.set(true);
          return this.svc.searchCatalog(q).pipe(catchError((e: ApiError) => {
            this.error.set(e.message);
            return of([] as CatalogOffering[]);
          }));
        }),
        takeUntilDestroyed(this.destroyRef),
      )
      .subscribe(found => {
        this.offerings.set(found);
        this.loading.set(false);
      });
    this.typed.next('');
    this.loadOrders();
    this.svc.listRecipients().subscribe({
      next: people => this.recipients.set(people),
      // Without permission to list people, an order is for the caller.
      error: () => this.recipients.set([]),
    });
  }

  search(q: string): void {
    this.typed.next(q.trim());
  }

  add(offering: CatalogOffering): void {
    this.cart.update(lines => {
      const existing = lines.find(l => l.offering.id === offering.id);
      return existing
        ? lines.map(l => (l === existing ? { ...l, quantity: l.quantity + 1 } : l))
        : [...lines, { offering, quantity: 1 }];
    });
  }

  setQuantity(line: CartLine, value: string): void {
    const quantity = Math.max(1, Math.min(1000, Math.floor(Number(value) || 1)));
    this.cart.update(lines => lines.map(l => (l === line ? { ...l, quantity } : l)));
  }

  remove(line: CartLine): void {
    this.cart.update(lines => lines.filter(l => l !== line));
  }

  placeOrder(): void {
    const requester = this.recipientId() || this.auth.userId();
    if (!requester || this.cart().length === 0) return;
    this.placing.set(true);
    this.error.set(null);
    this.svc.placeOrder(requester, this.cart()).subscribe({
      next: placed => {
        this.placing.set(false);
        this.cart.set([]);
        this.placedReference.set(placed.reference ?? placed.work_request_id);
        this.loadOrders();
      },
      error: (e: ApiError) => {
        this.placing.set(false);
        this.error.set(e.message);
      },
    });
  }

  cancel(itemId: string): void {
    this.svc.cancelOrderItem(itemId).subscribe({
      next: () => this.loadOrders(),
      error: (e: ApiError) => {
        this.error.set(e.message);
        this.loadOrders();
      },
    });
  }

  private loadOrders(): void {
    this.svc.myOrders().subscribe({
      next: orders => this.orders.set(orders),
      error: () => this.orders.set([]),
    });
  }
}
