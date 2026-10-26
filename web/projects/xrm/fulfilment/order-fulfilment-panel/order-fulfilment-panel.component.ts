import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiService, LangService, LocalDatePipe, TranslatePipe } from '@attome/base';

/** One shipment carrying a line (`LineShipment`). */
export interface LineShipment {
  shipment_id: string;
  carrier: string | null;
  tracking_number: string | null;
  status: string | null;
  quantity: number | null;
}

/** One line's fulfilment (`LineRollup`). */
export interface LineRollup {
  line_id: string;
  fulfilment_order_id: string;
  order_line_ref: string | null;
  product_ref: string | null;
  ordered: number;
  shipped: number;
  delivered: number;
  backordered: number;
  promised_date: string | null;
  status: string | null;
  shipments: LineShipment[];
}

/** A sales order's fulfilment (`GET /api/v1/fulfilment/orders?order_id=`). */
export interface OrderFulfilment {
  order_id: string;
  lines: LineRollup[];
}

/** Where a carrier's tracking number can be followed, when the carrier has a page. Pure. */
export function trackingUrl(carrier: string | null, tracking: string | null): string | null {
  if (!tracking) return null;
  const n = encodeURIComponent(tracking);
  switch (carrier) {
    case 'aramex': return `https://www.aramex.com/track/results?ShipmentNumber=${n}`;
    case 'smsa': return `https://www.smsaexpress.com/trackingdetails?tracknumbers=${n}`;
    case 'dhl': return `https://www.dhl.com/global-en/home/tracking.html?tracking-id=${n}`;
    default: return null;
  }
}

/**
 * F6-T17: a sales order's fulfilment, line by line — ordered, shipped,
 * delivered and backordered, the promised date in the person's calendar, and
 * each shipment with its tracking link. Shown on the order's Fulfilment tab.
 * Layout uses logical properties only, so it mirrors right to left.
 */
@Component({
  selector: 'xrm-order-fulfilment-panel',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalDatePipe, TranslatePipe],
  template: `
    <section class="of" [attr.dir]="dir()" data-testid="order-fulfilment">
      @if (loading()) {
        <p class="of-hint">{{ 'fulfilment.panel.loading' | translate }}</p>
      } @else if (error()) {
        <p class="of-hint" role="alert">{{ 'fulfilment.panel.error' | translate }}</p>
      } @else if (!lines().length) {
        <p class="of-hint" data-testid="order-fulfilment-empty">{{ 'fulfilment.panel.empty' | translate }}</p>
      } @else {
        <table class="of-table">
          <thead>
            <tr>
              <th scope="col">{{ 'fulfilment.panel.line' | translate }}</th>
              <th scope="col" class="of-num">{{ 'fulfilment.panel.ordered' | translate }}</th>
              <th scope="col" class="of-num">{{ 'fulfilment.panel.shipped' | translate }}</th>
              <th scope="col" class="of-num">{{ 'fulfilment.panel.delivered' | translate }}</th>
              <th scope="col" class="of-num">{{ 'fulfilment.panel.backordered' | translate }}</th>
              <th scope="col">{{ 'fulfilment.panel.promised' | translate }}</th>
              <th scope="col">{{ 'fulfilment.panel.shipments' | translate }}</th>
            </tr>
          </thead>
          <tbody>
            @for (line of lines(); track line.line_id) {
              <tr data-testid="order-fulfilment-line">
                <td>{{ line.order_line_ref || line.line_id }}</td>
                <td class="of-num">{{ line.ordered }}</td>
                <td class="of-num">{{ line.shipped }}</td>
                <td class="of-num">{{ line.delivered }}</td>
                <td class="of-num" [class.of-warn]="line.backordered > 0">{{ line.backordered }}</td>
                <td>
                  @if (line.promised_date) { {{ line.promised_date | localDate: dateFormat }} }
                </td>
                <td>
                  @for (s of line.shipments; track s.shipment_id) {
                    <span class="of-ship">
                      @if (link(s); as url) {
                        <a [href]="url" target="_blank" rel="noopener noreferrer"
                           data-testid="order-fulfilment-tracking">{{ s.tracking_number }}</a>
                      } @else {
                        {{ s.tracking_number || ('fulfilment.panel.noTracking' | translate) }}
                      }
                      <span class="of-status">{{ s.status }}</span>
                    </span>
                  }
                </td>
              </tr>
            }
          </tbody>
        </table>
      }
    </section>
  `,
  styles: [`
    .of { display: block; overflow-x: auto; }
    .of-hint { color: var(--color-text-muted); margin: 0; }
    .of-table { inline-size: 100%; border-collapse: collapse; font-size: 0.875rem; }
    .of-table th, .of-table td { text-align: start; padding-block: 0.375rem; padding-inline: 0.5rem;
      border-block-end: 1px solid var(--color-border); vertical-align: top; }
    .of-num { text-align: end; font-variant-numeric: tabular-nums; }
    .of-warn { color: var(--color-warning); font-weight: 600; }
    .of-ship { display: inline-flex; gap: 0.25rem; margin-inline-end: 0.5rem; }
    .of-status { color: var(--color-text-muted); }
  `],
})
export class OrderFulfilmentPanelComponent {
  private readonly api = inject(ApiService);
  private readonly lang = inject(LangService);

  /** The order's entity name (the record tab passes it; the panel reads orders only). */
  readonly entityName = input<string>('order');
  /** The sales order. */
  readonly recordId = input<string | null>(null);

  readonly lines = signal<LineRollup[]>([]);
  readonly loading = signal(false);
  readonly error = signal(false);
  readonly dir = computed(() => (this.lang.isRtl() ? 'rtl' : 'ltr'));
  readonly dateFormat: Intl.DateTimeFormatOptions = { dateStyle: 'medium' };

  constructor() {
    effect(() => {
      const id = this.recordId();
      if (id) this.load(id);
    });
  }

  link(s: LineShipment): string | null {
    return trackingUrl(s.carrier, s.tracking_number);
  }

  private load(orderId: string): void {
    this.loading.set(true);
    this.error.set(false);
    this.api.get<OrderFulfilment>('/api/v1/fulfilment/orders', { order_id: orderId }).subscribe({
      next: page => {
        this.lines.set(page.lines ?? []);
        this.loading.set(false);
      },
      error: () => {
        this.error.set(true);
        this.loading.set(false);
      },
    });
  }
}
