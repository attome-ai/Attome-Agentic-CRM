import {
  ChangeDetectionStrategy, Component, computed, effect, inject, input, signal,
} from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiError, ApiService, AuthService } from '@attome/base';
import { QueryService } from '@attome/xrm/core/query/data';
import { QueryColumnDef } from '@attome/xrm/core/query/data';
import { Block } from '../services/content-public.service';

/**
 * The curated Component-block allow-list — mirrors
 * `attome_content::blocks::ALLOWED_COMPONENTS` exactly. An editor's picker (and
 * the server's own validation) can only ever reference one of these keys;
 * there is no free-text/arbitrary-component path (coding-guidelines §8).
 * Each entry is inline markup rendered by the `@switch` below, not a
 * dynamically loaded component — four fixed options don't warrant
 * `NgComponentOutlet`'s lazy-loading machinery.
 */
export const ALLOWED_COMPONENT_KEYS = [
  'cta-banner', 'pricing-table', 'testimonial-grid', 'newsletter-signup',
] as const;

interface QueryRow { columns: QueryColumnDef[]; records: Record<string, unknown>[]; }

/**
 * Renders one block, read-only — the shared render path for both the
 * editor's canvas (preview of each block) and the public page view
 * (`ContentPageViewComponent`), so the two can never visually drift apart.
 *
 * `data_table`/`chart`/`form` all need a live, authenticated read (or write,
 * for `form`) against `/api/v1/query/execute` / generic entity CRUD — routes
 * that require a session. On the public, anonymous page view there is no
 * session, so these three render an honest "requires sign-in" notice rather
 * than firing a request guaranteed to 401. Publicly-servable live data/forms
 * would need their own new anonymous, rate-limited endpoints — a separate,
 * security-sensitive feature this pass deliberately did not build (see
 * D-367's "no nginx/reverse-proxy changes" scope note).
 */
@Component({
  selector: 'attome-content-block-view',
  standalone: true,
  // Self-imported: the `columns` case recurses into `ContentBlockViewComponent`
  // for each nested block.
  imports: [FormsModule, ContentBlockViewComponent],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./content-block-view.component.css'],
  templateUrl: './content-block-view.component.html',
})
export class ContentBlockViewComponent {
  readonly block = input.required<Block>();
  /** True on the public, anonymous page view — gates `form` outright (see class doc). */
  readonly isPublic = input(false);

  private readonly auth = inject(AuthService);
  private readonly querySvc = inject(QueryService);
  private readonly api = inject(ApiService);

  readonly authed = computed(() => this.auth.isLoggedIn());
  readonly requiresAuth = computed(() => true);

  readonly showTable = signal(false);
  private readonly queryDataSig = signal<QueryRow | null>(null);
  private readonly queryErrorSig = signal<string | null>(null);
  private lastQueryId: string | null = null;

  /** Plain (non-signal) form state — only ever read at submit time, never
   *  re-rendered elsewhere, so it doesn't need to participate in change
   *  detection the way the signal-backed properties above do. */
  formValues: Record<string, string> = {};
  readonly formSubmitting = signal(false);
  readonly formMessage = signal<string | null>(null);

  stringProp(key: string): string {
    const v = this.block().props[key];
    return typeof v === 'string' ? v : '';
  }

  private numberProp(key: string, fallback: number): number {
    const v = this.block().props[key];
    return typeof v === 'number' ? v : fallback;
  }

  readonly text = computed(() => this.stringProp('text'));

  readonly level = computed(() => this.numberProp('level', 2));

  readonly alertIcon = computed(() => {
    switch (this.stringProp('variant')) {
      case 'warning': return 'la-exclamation-triangle';
      case 'danger':  return 'la-times-circle';
      case 'success': return 'la-check-circle';
      default:        return 'la-info-circle';
    }
  });

  readonly columnBlocks = computed(() => {
    const raw = this.block().props['columns'];
    if (!Array.isArray(raw)) return [];
    return raw.map(col =>
      (col && typeof col === 'object' && Array.isArray((col as { blocks?: unknown }).blocks))
        ? (col as { blocks: Block[] }).blocks
        : []);
  });
  readonly columnsTemplate = computed(() => `repeat(${Math.max(this.columnBlocks().length, 1)}, 1fr)`);

  readonly componentKey = computed(() => this.stringProp('component_key'));

  readonly formFields = computed(() => {
    const raw = this.block().props['fields'];
    return Array.isArray(raw) ? raw.filter((f): f is string => typeof f === 'string') : [];
  });

  readonly queryData = computed(() => this.queryDataSig());
  readonly queryError = computed(() => this.queryErrorSig());

  readonly visibleColumns = computed(() =>
    (this.queryData()?.columns ?? []).filter(c => c.is_visible));

  readonly chartWidth = computed(() => Math.max(this.chartBars().length * 40, 200));
  readonly barWidth = computed(() => 24);

  readonly chartBars = computed(() => {
    const data = this.queryData();
    if (!data) return [];
    const cols = data.columns.filter(c => c.is_visible);
    const labelCol = cols[0]?.name;
    const valueCol = cols.find(c => c.name !== labelCol && ['integer', 'bigint', 'decimal'].includes(c.data_type))?.name
      ?? cols[1]?.name;
    if (!labelCol || !valueCol) return [];
    const raw = data.records.map(r => ({
      label: this.formatCell(r[labelCol]),
      value: Number(r[valueCol]) || 0,
    }));
    const max = Math.max(...raw.map(r => r.value), 1);
    return raw.map((r, i) => ({
      label: r.label,
      value: r.value,
      x: i * 40 + 4,
      height: (r.value / max) * 110,
      y: 120 - (r.value / max) * 110,
    }));
  });

  constructor() {
    // Reruns whenever a tracked signal changes, not just once — needed
    // because `block()`'s query_id can change (editor swaps the bound
    // query) without this component being torn down/recreated. The
    // `lastQueryId` guard keeps it from refetching every run for an
    // unrelated prop edit. Must be `effect()`, not a `computed()` called
    // immediately in the constructor: a required input's value isn't bound
    // yet when the constructor body runs, so reading `block()` synchronously
    // here throws NG0950 on every fresh instance (e.g. every "add block") —
    // `effect()` defers its first run until after Angular finishes binding
    // inputs.
    effect(() => {
      const kind = this.block().kind;
      if (kind !== 'data_table' && kind !== 'chart') return;
      if (this.isPublic() || !this.authed()) return;
      const queryId = this.stringProp('query_id');
      if (!queryId || queryId === this.lastQueryId) return;
      this.lastQueryId = queryId;
      this.queryDataSig.set(null);
      this.queryErrorSig.set(null);
      this.querySvc.execute({ query_id: queryId, page_size: this.numberProp('page_size', 10) }).subscribe({
        next: res => this.queryDataSig.set({ columns: res.data.columns, records: res.data.records }),
        error: () => this.queryErrorSig.set('Could not load this data.'),
      });
    });
  }

  formatCell(value: unknown): string {
    if (value === null || value === undefined) return '—';
    return String(value);
  }

  submitForm(event: SubmitEvent): void {
    event.preventDefault();
    const entity = this.stringProp('entity');
    if (!entity) return;
    this.formSubmitting.set(true);
    this.formMessage.set(null);
    // Reuses the generic entity CRUD create path directly (`POST
    // /api/v1/{entity}`) — no bespoke write endpoint for this block, same
    // path every other engine uses for record writes.
    this.api.post(`/api/v1/${entity}`, this.formValues).subscribe({
      next: () => {
        this.formSubmitting.set(false);
        this.formMessage.set('Submitted.');
        this.formValues = {};
      },
      error: (e: ApiError) => {
        this.formSubmitting.set(false);
        this.formMessage.set(e.message);
      },
    });
  }
}
