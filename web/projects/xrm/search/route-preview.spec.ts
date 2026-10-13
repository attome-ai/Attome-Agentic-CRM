import { describe, expect, it } from 'vitest';
import { normalizeAr, predictRoute } from './route-preview';

/**
 * These mirror `attome_search::router::tests::every_rule_is_pinned` and
 * `attome_search::lang::arabic`'s vectors case for case.
 *
 * That correspondence is the whole value: this file is an oracle for the search
 * lab, and an oracle that drifts from the thing it checks is worse than none —
 * it would report a mismatch on every query and train everyone to ignore the
 * verdict. When a rule changes in `router.rs`, the assertion that fails here is
 * the reminder that the mirror moved out of step.
 */
describe('normalizeAr', () => {
  it('folds alef variants onto bare alef', () => {
    expect(normalizeAr('أحمد')).toBe('احمد');
    expect(normalizeAr('إبراهيم')).toBe('ابراهيم');
    expect(normalizeAr('آمال')).toBe('امال');
  });

  it('folds taa marbuta to haa and alef maksura to ya', () => {
    expect(normalizeAr('شركة')).toBe('شركه');
    expect(normalizeAr('مصطفى')).toBe('مصطفي');
  });

  it('strips tashkeel and tatweel', () => {
    expect(normalizeAr('مُحَمَّد')).toBe('محمد');
    expect(normalizeAr('محـــمد')).toBe('محمد');
  });

  it('converts both Arabic-Indic digit ranges to ASCII', () => {
    expect(normalizeAr('٩٠٠١')).toBe('9001');
    expect(normalizeAr('۹۰۰۱')).toBe('9001');
  });

  it('lowercases Latin and collapses any whitespace run to one space', () => {
    expect(normalizeAr('  ACME   Trading\tLLC ')).toBe('acme trading llc');
  });

  it('is idempotent — re-normalizing a normalized string changes nothing', () => {
    const once = normalizeAr('أحمد مُحَمَّد ٩٠٠١');
    expect(normalizeAr(once)).toBe(once);
  });
});

describe('predictRoute', () => {
  it('Rule 1 — an identifier routes exact, for either audience', () => {
    expect(predictRoute('INV-9001', 'human').route).toBe('exact');
    expect(predictRoute('2024AB77', 'agent').route).toBe('exact');
    // Four or more digits and nothing else also counts.
    expect(predictRoute('9001', 'human').route).toBe('exact');
    // Arabic-Indic digits reach the same rule, because normalization runs first.
    expect(predictRoute('٩٠٠١', 'human').route).toBe('exact');
  });

  it('Rule 1 — a bare word is not an identifier, digits are what make one', () => {
    expect(predictRoute('acme', 'agent').route).not.toBe('exact');
    // Fewer than four digits with nothing else is not an identifier either.
    expect(predictRoute('900', 'agent').route).not.toBe('exact');
  });

  it('Rule 2 — quoting wins over the identifier test', () => {
    expect(predictRoute('"acme trading"', 'human').route).toBe('phrase');
    expect(predictRoute('"INV-9001"', 'human').route).toBe('phrase');
  });

  it('Rule 3 — one or two name tokens route to name lookup, for humans only', () => {
    expect(predictRoute('acme', 'human').route).toBe('name_lookup');
    expect(predictRoute('acme trading', 'human').route).toBe('name_lookup');
    // The one place the audiences genuinely differ: an agent that emitted two
    // words composed them as content and must not get prefix semantics.
    expect(predictRoute('acme trading', 'agent').route).toBe('hybrid');
  });

  it('Rule 4 — arithmetic language routes to a hint rather than retrieval', () => {
    expect(predictRoute('how many invoices are open', 'agent').route).toBe('aggregation');
    expect(predictRoute('total of unpaid invoices', 'human').route).toBe('aggregation');
    expect(predictRoute('كم عدد الفواتير المفتوحة', 'agent').route).toBe('aggregation');
  });

  it('Rule 4 — Arabic markers match after normalization, not before', () => {
    // Same phrase carrying tashkeel: the marker only matches once the
    // diacritics are stripped, which is exactly what the backend does too.
    expect(predictRoute('كَم عَدَد الفواتير', 'agent').route).toBe('aggregation');
  });

  it('Rule 5 — everything else is hybrid', () => {
    expect(predictRoute('wholesale electronics distributor', 'human').route).toBe('hybrid');
    expect(predictRoute('invoice', 'agent').route).toBe('hybrid');
  });

  it('an empty or whitespace-only query is hybrid, never a crash', () => {
    expect(predictRoute('', 'human').route).toBe('hybrid');
    expect(predictRoute('    ', 'agent').route).toBe('hybrid');
  });

  it('reports the rule that decided, so a mismatch is diagnosable', () => {
    expect(predictRoute('INV-9001', 'human').rule).toContain('Rule 1');
    expect(predictRoute('"acme"', 'human').rule).toContain('Rule 2');
    expect(predictRoute('acme', 'human').rule).toContain('Rule 3');
    expect(predictRoute('how many', 'human').rule).toContain('Rule 4');
    expect(predictRoute('a b c', 'human').rule).toContain('Rule 5');
  });

  it('exposes the normalized query the rules actually saw', () => {
    expect(predictRoute('  أحمد  ', 'human').normalized).toBe('احمد');
  });
});
