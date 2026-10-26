import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { forkJoin } from 'rxjs';
import { ProductPrice, SalesApiService, SalesLine, SalesLinePatch } from '../sales-api.service';

/** The feature that turns opportunity lines on. */
export const LINES_FLAG = 'sales.opportunity_lines';

/** What a person is typing into a line, before it is saved. */
export interface LineDraft {
  quantity: string;
  sales_price: string;
  discount_percent: string;
}

/** Currencies with three minor units, and with none. */
const THREE = new Set(['KWD', 'BHD', 'OMR', 'JOD', 'IQD', 'LYD', 'TND']);
const NONE = new Set(['JPY', 'KRW', 'VND', 'CLP', 'ISK', 'UGX']);

/** The minor units of a currency (ISO 4217): 3 for KWD, BHD and OMR, else 2. Pure. */
export function minorUnits(code: string | null | undefined): number {
  const c = (code ?? '').trim().toUpperCase();
  if (THREE.has(c)) return 3;
  if (NONE.has(c)) return 0;
  return 2;
}

/** An amount with its currency's minor units, in `locale`'s digits. Pure. */
export function formatMoney(value: number, code: string | null | undefined, locale: string): string {
  const digits = minorUnits(code);
  const text = new Intl.NumberFormat(locale, {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  }).format(Number.isFinite(value) ? value : 0);
  return code ? `${text} ${code.toUpperCase()}` : text;
}

function num(text: string | null | undefined): number {
  const n = Number.parseFloat((text ?? '').trim());
  return Number.isFinite(n) ? n : 0;
}

/**
 * A line's total as the person sees it while typing: quantity times the
 * sales price (else the list price), less the discount percent and the
 * discount amount. The server prices the line again on save. Pure.
 */
export function lineTotal(line: SalesLine, draft?: LineDraft): number {
  const quantity = num(draft?.quantity ?? line.quantity ?? '1');
  const price = draft?.sales_price?.trim()
    ? num(draft.sales_price)
    : num(line.sales_price ?? line.list_price);
  const percent = num(draft?.discount_percent ?? line.discount_percent);
  const total = quantity * price * (1 - percent / 100) - num(line.discount_amount);
  return Math.max(total, 0);
}

/** The total of every line, drafts included. Pure. */
export function draftTotal(lines: readonly SalesLine[], drafts: ReadonlyMap<string, LineDraft>): number {
  return lines.reduce((sum, l) => sum + lineTotal(l, drafts.get(l.id)), 0);
}

function draftOf(line: SalesLine): LineDraft {
  return {
    quantity: line.quantity ?? '1',
    sales_price: line.sales_price ?? '',
    discount_percent: line.discount_percent ?? '',
  };
}

/** The fields of `draft` that differ from the saved line. Pure. */
function changes(line: SalesLine, draft: LineDraft): SalesLinePatch {
  const patch: SalesLinePatch = {};
  const saved = draftOf(line);
  if (draft.quantity.trim() !== saved.quantity) patch.quantity = draft.quantity.trim();
  if (draft.sales_price.trim() !== saved.sales_price) patch.sales_price = draft.sales_price.trim();
  if (draft.discount_percent.trim() !== saved.discount_percent) {
    patch.discount_percent = draft.discount_percent.trim();
  }
  return patch;
}

/**
 * D6-T10: an opportunity's lines, as its Lines tab. Totals follow the typing
 * at once; a field is saved when it loses focus, through the line routes
 * with the opportunity's `row_version`, and the server's prices replace the
 * draft. Products are added from the opportunity's price list; a line can be
 * copied. A sync with the quote that finds both sides changed asks which
 * lines to keep. Cost shows only when the server sends it.
 */
@Component({
  selector: 'xrm-line-grid',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [TranslatePipe],
  styleUrls: ['./line-grid.component.css'],
  templateUrl: './line-grid.component.html',
})
export class LineGridComponent {
  private readonly sales = inject(SalesApiService);
  private readonly lang = inject(LangService);

  /** Given by the record tabs; always `opportunity` here. */
  readonly entityName = input<string>('opportunity');
  readonly recordId = input<string | null>(null);

  readonly lines = signal<SalesLine[] | null>(null);
  readonly drafts = signal<ReadonlyMap<string, LineDraft>>(new Map());
  readonly rowVersion = signal<number | null>(null);
  readonly currency = signal<string | null>(null);
  readonly priceList = signal<string | null>(null);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly query = signal('');
  readonly results = signal<ProductPrice[]>([]);
  readonly conflict = signal(false);

  /** `null` until the feature flag is read. */
  readonly enabled = signal<boolean | null>(null);
  readonly total = computed(() => draftTotal(this.lines() ?? [], this.drafts()));
  readonly showCost = computed(() => (this.lines() ?? []).some(l => 'unit_cost' in l));

  constructor() {
    this.sales.featureOn(LINES_FLAG).subscribe({
      next: on => this.enabled.set(on),
      error: () => this.enabled.set(false),
    });
    effect(() => {
      const id = this.recordId();
      if (id) this.load(id);
    });
  }

  money(value: number): string {
    return formatMoney(value, this.currency(), this.lang.intlLocale());
  }

  lineMoney(line: SalesLine): string {
    return this.money(lineTotal(line, this.drafts().get(line.id)));
  }

  draft(line: SalesLine): LineDraft {
    return this.drafts().get(line.id) ?? draftOf(line);
  }

  load(id: string): void {
    this.error.set(null);
    forkJoin({ lines: this.sales.lines(id), opportunity: this.sales.opportunity(id) }).subscribe({
      next: ({ lines, opportunity }) => {
        const data = opportunity.data as Record<string, unknown>;
        this.lines.set(lines);
        this.drafts.set(new Map());
        this.rowVersion.set(opportunity.row_version);
        this.currency.set(typeof data['currency'] === 'string' ? (data['currency'] as string) : null);
        this.priceList.set(typeof data['price_list_ref'] === 'string' ? (data['price_list_ref'] as string) : null);
      },
      error: (e: ApiError) => {
        this.lines.set([]);
        this.error.set(this.lang.errorText(e) || null);
      },
    });
  }

  /** Typing into a field: the totals follow at once; nothing is saved yet. */
  edit(line: SalesLine, field: keyof LineDraft, value: string): void {
    const next = new Map(this.drafts());
    next.set(line.id, { ...this.draft(line), [field]: value });
    this.drafts.set(next);
  }

  /** A field lost focus: save what changed, then show the server's prices. */
  commit(line: SalesLine): void {
    const id = this.recordId();
    const rv = this.rowVersion();
    const draft = this.drafts().get(line.id);
    if (!id || rv === null || !draft || this.busy()) return;
    const patch = changes(line, draft);
    if (Object.keys(patch).length === 0) return;
    this.busy.set(true);
    this.sales.updateLine(id, line.id, rv, patch).subscribe({
      next: () => {
        this.busy.set(false);
        this.load(id);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  search(q: string): void {
    this.query.set(q);
    const list = this.priceList();
    if (!list || q.trim().length < 2) {
      this.results.set([]);
      return;
    }
    this.sales.products(list, q.trim()).subscribe({
      next: items => this.results.set(items),
      error: () => this.results.set([]),
    });
  }

  add(product: ProductPrice): void {
    this.addLine({ product_ref: product.product_id, quantity: '1' });
    this.query.set('');
    this.results.set([]);
  }

  copy(line: SalesLine): void {
    if (!line.product_ref) return;
    const d = this.draft(line);
    this.addLine({
      product_ref: line.product_ref,
      quantity: d.quantity || '1',
      ...(d.sales_price ? { sales_price: d.sales_price } : {}),
      ...(d.discount_percent ? { discount_percent: d.discount_percent } : {}),
    });
  }

  /** Asks the quote to take this deal's lines; both sides changed asks the person. */
  syncToQuote(): void {
    this.runSync('to_quote', false);
  }

  keepOpportunityLines(): void {
    this.runSync('to_quote', true);
  }

  takeQuoteLines(): void {
    this.runSync('from_quote', true);
  }

  private runSync(direction: 'from_quote' | 'to_quote', force: boolean): void {
    const id = this.recordId();
    if (!id || this.busy()) return;
    this.busy.set(true);
    this.sales.sync(id, direction, force).subscribe({
      next: () => {
        this.busy.set(false);
        this.conflict.set(false);
        this.load(id);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        if (e?.status === 409 && (e.code === 'sync_both_changed' || !e.code)) {
          this.conflict.set(true);
        } else {
          this.fail(e);
        }
      },
    });
  }

  private addLine(body: { product_ref: string } & SalesLinePatch): void {
    const id = this.recordId();
    const rv = this.rowVersion();
    if (!id || rv === null || this.busy()) return;
    this.busy.set(true);
    this.sales.addLine(id, rv, body).subscribe({
      next: () => {
        this.busy.set(false);
        this.load(id);
      },
      error: (e: ApiError) => this.fail(e),
    });
  }

  private fail(e: ApiError): void {
    this.busy.set(false);
    this.error.set(this.lang.errorText(e) || null);
    const id = this.recordId();
    // A version conflict means someone else saved: show their lines.
    if (id && e?.status === 409) this.load(id);
  }
}
