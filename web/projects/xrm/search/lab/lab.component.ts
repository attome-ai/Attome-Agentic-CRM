import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { TranslatePipe } from '@attome/base';
import {
  SearchHit,
  SearchResponse,
  SearchService,
  formatTotal,
  groupHits,
  isRelaxed,
  matchQuality,
} from '@attome/xrm/search/omni';
import { PredictedRoute, predictRoute } from '../route-preview';

/**
 * Pass/fail for the one check that does not depend on what is indexed.
 *
 * Deliberately two-valued: a probe that ran either routed the way the rules
 * say it should or it did not, and there is no third state worth a colour.
 */
type Verdict = 'pass' | 'fail';

/** One executed probe: what was asked, what came back, and how long it took. */
interface Probe {
  id: number;
  /** The feature card it came from, or `ad-hoc`. Keys the per-card result strip. */
  key: string;
  feature: string;
  query: string;
  audience: 'human' | 'agent';
  /** Wall clock, client-side. See the note in the template about what it includes. */
  ms: number;
  status: number | 'error';
  hits: SearchHit[];
  total: string;
  route: string;
  /** What the documented rules say the route should have been. */
  expectedRoute: PredictedRoute;
  /** Which rule produced `expectedRoute` — shown so a mismatch is diagnosable. */
  rule: string;
  routeHint: string | null;
  degraded: string[];
  relaxed: boolean;
  impressionId: string | null;
  verdict: Verdict;
  /** Why the verdict is what it is, in one line. Empty when it simply passed. */
  reason: string;
  error?: string;
}

/** A canned probe: one search feature, with the query that exercises it. */
interface Feature {
  key: string;
  label: string;
  query: string;
  audience?: 'human' | 'agent';
  /** What to look at in the result — the thing that tells you it worked. */
  expect: string;
  /**
   * A non-200 this feature is *supposed* to produce. Only the term-cap guard
   * has one: for every other card an error is a failure, and for that one an
   * error is the pass.
   */
  expectStatus?: number;
}

/** A feature card's live state — the query is editable, so it lives in a signal. */
interface Card extends Feature {
  /** Current text in the card's input. Starts as `query`, then whatever you type. */
  current: string;
  currentAudience: 'human' | 'agent';
}

/**
 * The search lab — every retrieval feature, individually, with timings.
 *
 * ## Why a page rather than a test
 *
 * The harnesses (`ranking_eval`, `coverage_eval`) answer "is relevance holding"
 * against a fixed corpus. They cannot answer "what does *this* deployment's
 * search do with *this* query", which is the question anyone actually has when
 * they suspect search is misbehaving — and the corpus that matters is the
 * customer's, not the fixture's.
 *
 * So this runs the real endpoint, as the logged-in caller, against live data.
 * Everything it shows is what that caller would get; nothing here bypasses the
 * permission filter, and it could not — it goes through `GET /api/v1/search`
 * like every other client.
 *
 * ## Every query is editable, and the verdict still works
 *
 * The canned queries are starting points, not the point: each card's input is
 * editable, so a feature can be exercised against the deployment's own data
 * ("does *our* customer name survive the alef fold") rather than against a
 * fixture name that was never indexed here. Type over it and run.
 *
 * That is why the verdict checks **routing**, not hits. Routing is a pure
 * function of the query text (`route-preview.ts` mirrors the Rule 1-5 contract
 * client-side), so it is decidable for a string typed thirty seconds ago on a
 * deployment whose corpus this page knows nothing about. Hit counts are not:
 * zero hits is equally consistent with a broken fuzzy leg and with nobody
 * having indexed that record yet, and a lab that painted the second case red
 * would train everyone to ignore red. Hits are reported, never graded.
 *
 * ## What the timing does and does not include
 *
 * `ms` is **client-side wall clock**: network, TLS, the server's own work, and
 * JSON parsing. It is the number a user experiences, which makes it the right
 * default — but it is not comparable to `P-search-and-retrieval` §11's budgets,
 * which are server-side. On loopback the gap is small; over a real network it
 * is the RTT. The panel says so rather than letting anyone read a red number as
 * a server problem.
 *
 * The server's own view is `attome_search_duration_seconds` on the Prometheus
 * listener; a persistent gap between the two is a network or serialisation
 * problem, which is a genuinely useful thing to be able to see.
 */
@Component({
  selector: 'attome-search-lab',
  standalone: true,
  imports: [FormsModule, TranslatePipe],
  changeDetection: ChangeDetectionStrategy.OnPush,
  styleUrls: ['./lab.component.css'],
  templateUrl: './lab.component.html',
})
export class SearchLabComponent {
  private readonly service = inject(SearchService);
  private nextId = 1;

  readonly query = signal('');
  readonly audience = signal<'human' | 'agent'>('human');
  readonly pageSize = signal(10);
  readonly busy = signal(false);
  readonly probes = signal<Probe[]>([]);

  /**
   * One entry per retrieval feature, each with a query that exercises *that
   * leg* and a note saying what to look at.
   *
   * The `expect` text matters more than it looks: a page of buttons that
   * produce results tells you nothing unless you know which result would be
   * wrong. Every entry names the observable that means the feature is working.
   */
  private readonly features: Feature[] = [
    {
      key: 'exact',
      label: 'R1 exact key',
      query: 'INV-9001',
      expect: 'Rank 1, legs include R1.exact_key, route "exact". Fastest path — §11 budgets it under 5 ms server-side.',
    },
    {
      key: 'prefix',
      label: 'R2 prefix / typeahead',
      query: 'ACME Tra',
      expect: 'Legs include R2.prefix. This is the per-keystroke path, so watch the ms column here above all others.',
    },
    {
      key: 'lexical',
      label: 'R3 lexical (full text)',
      query: 'wholesale electronics distributor',
      expect: 'Legs include R3.lexical. Matches body text, not just titles. Three tokens on purpose — one or two would route to name lookup instead.',
    },
    {
      key: 'fuzzy',
      label: 'R5 fuzzy / typo',
      query: 'Zenth Logistcs',
      expect: 'Legs include R5.fuzzy and the row is marked "relaxed" — a misspelling should still find the record.',
    },
    {
      key: 'arabic-taa',
      label: 'Arabic — ة typed as ه',
      query: 'شركه',
      expect: 'Must return the same records as شركة. Zero results here means normalization is not running — the failure that looks like "no such customer".',
    },
    {
      key: 'arabic-alef',
      label: 'Arabic — bare ا for أ',
      query: 'احمد',
      expect: 'Must match أحمد. Same normalization path, different fold.',
    },
    {
      key: 'arabic-digits',
      label: 'Arabic-Indic digits',
      query: '٩٠٠١',
      expect: 'Must behave as 9001 — a user reading an Arabic-locale document types these. Routes "exact" only because normalization folded the digits first.',
    },
    {
      key: 'mixed',
      label: 'Mixed Arabic / Latin',
      query: 'فاتورة ACME',
      expect: 'Routine in the GCC. Per-token stemming is what makes it work.',
    },
    {
      key: 'aggregation',
      label: 'Rule 4 — aggregation routing',
      query: 'how many invoices are open',
      audience: 'agent',
      expect: 'Route should be "aggregation" with ZERO hits and a tool hint. Returning ten plausible rows here is the bug — the model would add them up wrong.',
    },
    {
      key: 'aggregation-ar',
      label: 'Rule 4 — Arabic aggregation',
      query: 'كم عدد الفواتير المفتوحة',
      audience: 'agent',
      expect: 'Same routing decision in Arabic. A rule that held only in English would fail silently in the primary market.',
    },
    {
      key: 'phrase',
      label: 'Quoted phrase',
      query: '"ACME Trading LLC"',
      expect: 'Route "phrase", no fuzzy relaxation — quoting means these words in this order.',
    },
    {
      key: 'agent-floor',
      label: 'Agent tuning (score floor)',
      query: 'invoice',
      audience: 'agent',
      expect: 'Should return FEWER hits than the same query as human — flip the audience select and compare. A human ignores an irrelevant fourth result; a model cites it.',
    },
    {
      key: 'broad',
      label: 'Broad query — total kind',
      query: 'a',
      expect: 'Watch the total column: "500+ results" means the candidate ceiling was hit and the count is a floor, not a number.',
    },
    {
      key: 'empty',
      label: 'No results',
      query: 'zzzzqqqxyzzy',
      expect: 'Zero hits and no error. An empty result is a correct answer — the feature is that it comes back fast and says nothing rather than erroring.',
    },
    {
      key: 'long',
      label: 'Term cap (DoS guard)',
      query: Array.from({ length: 40 }, (_, i) => `term${i}`).join(' '),
      expect: 'Should be REJECTED (422). GIN cost is roughly linear in term count, so a long paste is a cheap authenticated DoS — rejecting beats truncating.',
      expectStatus: 422,
    },
  ];

  readonly cards = signal<Card[]>(
    this.features.map((f) => ({ ...f, current: f.query, currentAudience: f.audience ?? 'human' })),
  );

  /**
   * The most recent probe per card, so a card can show its own outcome without
   * anyone scanning the table for the matching row. `probes` is newest-first,
   * so the first entry seen for a key is the latest one.
   */
  readonly latest = computed(() => {
    const byKey = new Map<string, Probe>();
    for (const p of this.probes()) if (!byKey.has(p.key)) byKey.set(p.key, p);
    return byKey;
  });

  readonly summary = computed(() => {
    const all = this.probes();
    if (all.length === 0) return '';
    const failed = all.filter((p) => p.verdict === 'fail').length;
    const timed = all.filter((p) => p.status !== 'error');
    const verdicts = `${all.length} probe(s) · ${all.length - failed} passed · ${failed} failed`;
    if (timed.length === 0) return verdicts;
    const times = timed.map((p) => p.ms).sort((a, b) => a - b);
    const p50 = times[Math.floor(times.length * 0.5)];
    const empty = timed.filter((p) => p.hits.length === 0).length;
    return `${verdicts} · median ${p50} ms · slowest ${times[times.length - 1]} ms · ${empty} returned nothing`;
  });

  /**
   * True when nothing at all came back across every successful probe — the
   * signature of an empty index rather than of a search problem, and worth
   * saying once at the top instead of thirteen times in the notes column.
   */
  readonly nothingIndexed = computed(() => {
    const ok = this.probes().filter((p) => p.status === 200);
    return ok.length > 0 && ok.every((p) => p.hits.length === 0);
  });

  /** The route this card's *current* text should take. Recomputed as you type. */
  preview(card: Card): { route: PredictedRoute; rule: string } {
    return predictRoute(card.current, card.currentAudience);
  }

  setQuery(key: string, value: string): void {
    this.patch(key, (c) => ({ ...c, current: value }));
  }

  setAudience(key: string, value: 'human' | 'agent'): void {
    this.patch(key, (c) => ({ ...c, currentAudience: value }));
  }

  reset(key: string): void {
    this.patch(key, (c) => ({ ...c, current: c.query, currentAudience: c.audience ?? 'human' }));
  }

  resetAll(): void {
    this.cards.update((all) =>
      all.map((c) => ({ ...c, current: c.query, currentAudience: c.audience ?? 'human' })),
    );
  }

  quality(hit: SearchHit): string {
    return matchQuality(hit);
  }

  groupLabel(hits: SearchHit[]): string {
    return groupHits(hits)
      .map((g) => `${g.entity} (${g.hits.length})`)
      .join(', ');
  }

  run(key: string, feature: string, query: string, audience: 'human' | 'agent'): void {
    if (!query.trim()) return;
    const expectStatus = this.features.find((f) => f.key === key)?.expectStatus;
    const predicted = predictRoute(query, audience);
    this.busy.set(true);
    // `performance.now()` rather than `Date.now()`: monotonic, and immune to a
    // clock adjustment landing mid-probe and producing a negative duration.
    const started = performance.now();

    const base = {
      id: this.nextId++,
      key,
      feature,
      query,
      audience,
      expectedRoute: predicted.route,
      rule: predicted.rule,
    };

    this.service.search(query, { pageSize: this.pageSize(), audience }).subscribe({
      next: (response: SearchResponse) => {
        const routeOk = response.route === predicted.route;
        const wanted = expectStatus !== undefined;
        this.push({
          ...base,
          ms: Math.round(performance.now() - started),
          status: 200,
          hits: response.items ?? [],
          total: formatTotal(response.total),
          route: response.route,
          routeHint: response.route_hint?.tool ?? null,
          degraded: response.degraded ?? [],
          relaxed: isRelaxed(response.items ?? []),
          impressionId: response.impression_id ?? null,
          // A card that declares an expected rejection and got a 200 has failed
          // — the guard it exists to prove did not fire.
          verdict: wanted ? 'fail' : routeOk ? 'pass' : 'fail',
          reason: wanted
            ? `expected ${expectStatus}, the request was accepted`
            : routeOk
              ? ''
              : `routed "${response.route}", rules say "${predicted.route}"`,
        });
        this.busy.set(false);
      },
      error: (err: unknown) => {
        // A rejection is a result, not a crash — the term-cap probe expects one,
        // and a lab that hid it would hide the guard it is testing.
        const status = (err as { status?: number })?.status;
        const asExpected = expectStatus !== undefined && status === expectStatus;
        this.push({
          ...base,
          ms: Math.round(performance.now() - started),
          status: 'error',
          hits: [],
          total: '—',
          route: '—',
          routeHint: null,
          degraded: [],
          relaxed: false,
          impressionId: null,
          verdict: asExpected ? 'pass' : 'fail',
          reason: asExpected
            ? ''
            : expectStatus !== undefined
              ? `expected ${expectStatus}, got ${status ?? 'a transport failure'}`
              : 'request failed',
          error: this.describe(err),
        });
        this.busy.set(false);
      },
    });
  }

  /**
   * Runs every card in sequence, not in parallel, using whatever each one
   * currently holds — edits included.
   *
   * Parallel would be faster and the timings would be worthless: fifteen
   * concurrent searches contend for the same pool and the same GIN indexes, so
   * every number would measure the batch rather than the feature.
   */
  async runAll(): Promise<void> {
    for (const c of this.cards()) {
      this.run(c.key, c.label, c.current, c.currentAudience);
      // Wait for the in-flight probe before starting the next.
      while (this.busy()) {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
    }
  }

  private patch(key: string, change: (card: Card) => Card): void {
    this.cards.update((all) => all.map((c) => (c.key === key ? change(c) : c)));
  }

  private push(probe: Probe): void {
    this.probes.update((all) => [probe, ...all]);
  }

  private describe(err: unknown): string {
    const e = err as { status?: number; error?: { message?: string }; message?: string };
    const status = e?.status ? `${e.status} ` : '';
    return `${status}${e?.error?.message ?? e?.message ?? 'request failed'}`;
  }
}
