import { ChangeDetectionStrategy, Component, computed, effect, inject, input, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ApiError, LangService, TranslatePipe } from '@attome/base';
import { forkJoin } from 'rxjs';
import {
  ConvertMode, DuplicateMatch, LeadConvertApiService, LeadConvertBody, LeadConverted, LeadConvertPreview, LeadHead,
} from '../lead-convert-api';

/** One target's choice in the dialog. */
export interface TargetChoice {
  mode: ConvertMode;
  /** The record to link, with `link`. */
  id: string | null;
}

/** A match as the dialog lists it. */
export interface MatchRow {
  id: string;
  name: string;
  rule: string;
  /** The rule's score, as a whole percent. */
  percent: number;
}

/** The body a set of choices sends; `link` without a record falls back to `create`. Pure. */
export function convertBody(account: TargetChoice, contact: TargetChoice, opportunity: TargetChoice): LeadConvertBody {
  const wire = (c: TargetChoice) =>
    c.mode === 'link' && c.id ? { mode: 'link', id: c.id } : { mode: c.mode === 'link' ? 'create' : c.mode };
  return { account: wire(account), contact: wire(contact), opportunity: wire(opportunity) };
}

/** A preview's value map as label/value lines, empty values left out. Pure. */
export function valueLines(values: Record<string, unknown>): { field: string; value: string }[] {
  return Object.entries(values)
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([field, v]) => ({ field, value: typeof v === 'object' ? JSON.stringify(v) : String(v) }));
}

/**
 * D3-T3: a lead's Convert tab. It shows what the account, contact and
 * opportunity would hold (the server's conversion map, D3-T2) and the
 * existing accounts and contacts the duplicate rules say they would repeat;
 * for each the person creates a new record or links the match, may skip the
 * contact or the opportunity, and confirms. The server checks the lead's
 * version, its state and the person's access; the answer links the new
 * records, and Undo reverses the conversion while the server still allows it.
 */
@Component({
  selector: 'xrm-sales-lead-convert',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, TranslatePipe],
  templateUrl: './lead-convert.component.html',
  styleUrl: './lead-convert.component.css',
})
export class LeadConvertComponent {
  private readonly leads = inject(LeadConvertApiService);
  private readonly lang = inject(LangService);

  readonly entityName = input('lead');
  readonly recordId = input<string | null>(null);

  readonly lead = signal<LeadHead | null>(null);
  readonly preview = signal<LeadConvertPreview | null>(null);
  readonly accountMatches = signal<MatchRow[]>([]);
  readonly contactMatches = signal<MatchRow[]>([]);
  readonly account = signal<TargetChoice>({ mode: 'create', id: null });
  readonly contact = signal<TargetChoice>({ mode: 'create', id: null });
  readonly opportunity = signal<TargetChoice>({ mode: 'create', id: null });
  readonly loading = signal(false);
  readonly busy = signal(false);
  readonly error = signal<string | null>(null);
  readonly converted = signal<LeadConverted | null>(null);
  readonly undone = signal(false);

  readonly accountLines = computed(() => valueLines(this.preview()?.account ?? {}));
  readonly contactLines = computed(() => valueLines(this.preview()?.contact ?? {}));
  readonly opportunityLines = computed(() => valueLines(this.preview()?.opportunity ?? {}));
  /** Only a qualified (or new) lead converts; the server says so too. */
  readonly convertible = computed(() => {
    const status = this.lead()?.status;
    return status !== 'converted' && status !== 'disqualified';
  });

  constructor() {
    effect(() => {
      const id = this.recordId();
      if (id) this.load(id);
    });
  }

  private load(id: string): void {
    this.loading.set(true);
    this.error.set(null);
    forkJoin({ lead: this.leads.lead(id), preview: this.leads.preview(id) }).subscribe({
      next: ({ lead, preview }) => {
        this.lead.set(lead);
        this.preview.set(preview);
        this.loading.set(false);
        this.named('account', preview.account_matches);
        this.named('contact', preview.contact_matches);
      },
      error: (e: ApiError) => {
        this.loading.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  /** Lists the matches, then fills in their names. */
  private named(entity: 'account' | 'contact', matches: DuplicateMatch[]): void {
    const target = entity === 'account' ? this.accountMatches : this.contactMatches;
    const rows = matches.map(m => ({ id: m.record_id, name: m.record_id, rule: m.rule_name, percent: Math.round(m.score * 100) }));
    target.set(rows);
    if (!rows.length) return;
    forkJoin(rows.map(r => this.leads.matchName(entity, r.id))).subscribe({
      next: names => target.set(rows.map((r, i) => ({ ...r, name: names[i] ?? r.id }))),
      // A name that cannot be read leaves the id showing.
      error: () => undefined,
    });
  }

  choose(target: 'account' | 'contact' | 'opportunity', mode: ConvertMode, id: string | null = null): void {
    this[target].set({ mode, id });
  }

  isLinked(target: 'account' | 'contact', id: string): boolean {
    const c = this[target]();
    return c.mode === 'link' && c.id === id;
  }

  confirm(): void {
    const lead = this.lead();
    if (!lead || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.leads.convert(lead.id, convertBody(this.account(), this.contact(), this.opportunity()), lead.row_version).subscribe({
      next: r => {
        this.busy.set(false);
        this.converted.set(r);
        this.lead.set({ ...lead, status: 'converted' });
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }

  undo(): void {
    const done = this.converted();
    if (!done || this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    this.leads.undo(done.conversion_id).subscribe({
      next: () => {
        this.busy.set(false);
        this.converted.set(null);
        this.undone.set(true);
        this.load(done.lead_id);
      },
      error: (e: ApiError) => {
        this.busy.set(false);
        this.error.set(this.lang.errorText(e));
      },
    });
  }
}
