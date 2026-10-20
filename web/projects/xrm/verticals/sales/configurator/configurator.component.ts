import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { ApiError, ApiService, LangService, LocalNumberPipe, TranslatePipe } from '@attome/base';
import { EntityService } from '@attome/xrm/core/entity';
import { forkJoin, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';

/** One option a question offers. */
export interface OptionChoice {
  productId: string;
  name: string;
  nameAr: string | null;
  listPrice: number | null;
}

/** One option group, asked as a question. */
export interface OptionQuestion {
  id: string;
  name: string;
  nameAr: string | null;
  min: number;
  max: number | null;
  options: OptionChoice[];
}

/** `attome_sales::cpq::SalesCpqProblem`. */
export interface CpqProblem {
  code: string;
  group_id: string | null;
  option_id: string | null;
  other_option_id: string | null;
  rule_id: string | null;
  min: number | null;
  max: number | null;
  chosen: number | null;
  message: string | null;
}

interface PricedProduct {
  product_id: string;
  name: string | null;
  name_ar: string | null;
  list_price: string | null;
}

/** The list-price total of a configuration: the bundle plus each chosen option. Pure. */
export function listTotal(bundlePrice: number | null, options: OptionChoice[], chosen: ReadonlySet<string>): number {
  return options
    .filter(o => chosen.has(o.productId))
    .reduce((sum, o) => sum + (o.listPrice ?? 0), bundlePrice ?? 0);
}

/**
 * The bundle configurator (roadmap F1-T3): each option group of a bundle
 * product is a question (pick one, or pick up to N), with the defaults
 * already chosen. Every change is checked by the server
 * (`POST /api/v1/sales/cpq/validate`, the same rules an agent gets) and
 * each problem is explained; the price is the bundle's list price plus
 * the chosen options' from the price list, updated as choices change. The
 * quote line itself is priced by the CPQ waterfall when it is saved.
 * Arabic names are used in Arabic; layout uses logical properties only.
 */
@Component({
  selector: 'xrm-configurator',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [LocalNumberPipe, TranslatePipe],
  template: `
    <section class="cfg" aria-labelledby="cfg-title">
      <h2 id="cfg-title">{{ 'configurator.title' | translate }}</h2>
      @if (error(); as message) { <p class="cfg-error" role="alert">{{ message }}</p> }
      @for (q of questions(); track q.id) {
        <fieldset class="cfg-q" [attr.data-question]="q.id">
          <legend>{{ label(q.name, q.nameAr) }}
            <small>{{ (q.max === 1 ? 'configurator.pickOne' : 'configurator.pickUpTo') | translate: { max: q.max ?? q.options.length, min: q.min } }}</small>
          </legend>
          @for (o of q.options; track o.productId) {
            <label class="cfg-option">
              <input [type]="q.max === 1 ? 'radio' : 'checkbox'" [name]="q.id" [attr.data-option]="o.productId"
                     [checked]="chosen().has(o.productId)" (change)="toggle(q, o.productId)" />
              <span>{{ label(o.name, o.nameAr) }}</span>
              @if (o.listPrice !== null) { <span class="cfg-price">{{ o.listPrice | localNumber }}</span> }
            </label>
          }
        </fieldset>
      }
      @if (problems().length) {
        <ul class="cfg-problems" role="status">
          @for (p of problems(); track $index) {
            <li data-problem>{{ explain(p) }}</li>
          }
        </ul>
      }
      <p class="cfg-total">
        <span>{{ 'configurator.total' | translate }}</span>
        <strong data-total>{{ total() | localNumber }}</strong>
      </p>
    </section>
  `,
  styles: [`
    :host { display: block; }
    .cfg { display: flex; flex-direction: column; gap: 0.75rem; padding-block: 1rem; padding-inline: 1rem; }
    .cfg h2 { margin-block: 0; font-size: 1.125rem; }
    .cfg-q { border: 1px solid var(--color-border); border-radius: 0.5rem; padding-block: 0.5rem; padding-inline: 0.75rem; }
    .cfg-q legend small { margin-inline-start: 0.5rem; color: var(--color-text-secondary); font-weight: normal; }
    .cfg-option { display: flex; gap: 0.5rem; align-items: center; padding-block: 0.25rem; }
    .cfg-price { margin-inline-start: auto; color: var(--color-text-secondary); }
    .cfg-problems { margin: 0; padding-inline-start: 1.25rem; color: var(--color-danger); }
    .cfg-total { display: flex; justify-content: space-between; margin: 0; font-size: 1.0625rem; }
    .cfg-error { color: var(--color-danger); margin: 0; }
  `],
})
export class ConfiguratorComponent {
  private readonly api = inject(ApiService);
  private readonly entities = inject(EntityService);
  private readonly lang = inject(LangService);

  /** The bundle product. */
  readonly bundleId = input<string | null>(null);
  /** The price list the prices come from (none: no prices shown). */
  readonly priceListId = input<string | null>(null);

  readonly questions = signal<OptionQuestion[]>([]);
  readonly chosen = signal<ReadonlySet<string>>(new Set());
  readonly problems = signal<CpqProblem[]>([]);
  readonly bundlePrice = signal<number | null>(null);
  readonly error = signal<string | null>(null);

  readonly total = computed(() =>
    listTotal(this.bundlePrice(), this.questions().flatMap(q => q.options), this.chosen()));

  constructor() {
    effect(() => {
      const bundle = this.bundleId();
      const priceList = this.priceListId();
      untracked(() => { if (bundle) this.load(bundle, priceList); });
    });
  }

  label(name: string, nameAr: string | null): string {
    return this.lang.current() === 'ar' && nameAr ? nameAr : name;
  }

  toggle(question: OptionQuestion, productId: string): void {
    const next = new Set(this.chosen());
    if (question.max === 1) {
      for (const o of question.options) next.delete(o.productId);
      next.add(productId);
    } else if (next.has(productId)) {
      next.delete(productId);
    } else {
      next.add(productId);
    }
    this.chosen.set(next);
    this.validate();
  }

  /** A problem in the reader's words. */
  explain(p: CpqProblem): string {
    if (p.code === 'rule_failed' && p.message) return p.message;
    const name = (id: string | null) => {
      const all = this.questions().flatMap(q => q.options);
      const o = all.find(x => x.productId === id);
      if (o) return this.label(o.name, o.nameAr);
      const q = this.questions().find(x => x.id === id);
      return q ? this.label(q.name, q.nameAr) : '';
    };
    return this.lang.translate(`configurator.problem.${p.code}`, {
      group: name(p.group_id),
      option: name(p.option_id),
      other: name(p.other_option_id),
      min: p.min ?? 0,
      max: p.max ?? 0,
    });
  }

  private load(bundle: string, priceList: string | null): void {
    this.error.set(null);
    const prices$ = priceList
      ? this.api.get<{ items: PricedProduct[] }>(
          `/api/v1/sales/price-lists/${encodeURIComponent(priceList)}/products`, { page_size: '200' })
          .pipe(map(page => page.items), catchError(() => of([] as PricedProduct[])))
      : of([] as PricedProduct[]);
    forkJoin({
      groups: this.entities.list('product_option_group', {
        filters: [{ field: 'bundle_product_ref', op: 'eq', value: bundle }],
        sorts: [{ field: 'sort_order', dir: 'asc' }],
        limit: 50,
      }),
      prices: prices$,
    }).subscribe({
      next: ({ groups, prices }) => {
        const price = (id: string) => {
          const p = prices.find(x => x.product_id === id);
          return p?.list_price != null ? Number(p.list_price) : null;
        };
        this.bundlePrice.set(price(bundle));
        if (!groups.data.length) { this.questions.set([]); return; }
        forkJoin(groups.data.map(g => this.entities.list('product_option', {
          filters: [{ field: 'group_ref', op: 'eq', value: g.id }],
          limit: 100,
        }))).subscribe({
          next: lists => {
            const defaults = new Set<string>();
            const questions = groups.data.map((g, i) => ({
              id: g.id,
              name: String(g.data['name'] ?? ''),
              nameAr: (g.data['name_ar'] as string | null) ?? null,
              min: Number(g.data['min_choices'] ?? 0),
              max: g.data['max_choices'] == null ? null : Number(g.data['max_choices']),
              options: lists[i].data.map(o => {
                const id = String(o.data['product_ref'] ?? '');
                if (o.data['is_default'] === true) defaults.add(id);
                const p = prices.find(x => x.product_id === id);
                return { productId: id, name: p?.name ?? id, nameAr: p?.name_ar ?? null, listPrice: price(id) };
              }),
            }));
            this.questions.set(questions);
            this.chosen.set(defaults);
            this.validate();
          },
          error: (e: ApiError) => this.error.set(e.message),
        });
      },
      error: (e: ApiError) => this.error.set(e.message),
    });
  }

  private validate(): void {
    const bundle = this.bundleId();
    if (!bundle) return;
    this.api.post<{ valid: boolean; problems: CpqProblem[] }>('/api/v1/sales/cpq/validate', {
      bundle_product_id: bundle,
      chosen: [...this.chosen()],
    }).subscribe({
      next: r => this.problems.set(r.problems),
      error: (e: ApiError) => this.error.set(e.message),
    });
  }
}
