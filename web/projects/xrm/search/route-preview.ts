/**
 * A client-side mirror of the backend's routing rules, used by the search lab
 * as an **independent oracle**.
 *
 * ## Why duplicate backend logic at all
 *
 * The lab's whole job is answering "did search do the right thing with *this*
 * query". Showing the route the server picked answers half of that — you still
 * have to know which route it *should* have picked, and for a query you just
 * typed, nothing on the page knows that. So this predicts the route from the
 * documented Rule 1-5 contract (`attome_search::router::route`) and the lab shows
 * both. Agreement is the normal case; a disagreement is the finding.
 *
 * That makes the duplication the point rather than a smell: an oracle that
 * called the same code it is checking would agree with a broken router, and a
 * lab that only echoed the server's own answer could never surface a routing
 * regression at all. The cost is honest and bounded — if the rules change, this
 * file and `route-preview.spec.ts` change with them, and until they do the lab
 * reports a mismatch rather than silently agreeing.
 *
 * Mirrors, exactly and in order:
 *   - `attome_search::lang::arabic::normalize_ar` (tashkeel, tatweel, letter
 *     folds, both Arabic-Indic digit ranges, lowercase, whitespace collapse)
 *   - `attome_search::router::route` (rules 2, 1, 4, 3, 5 — in that evaluation
 *     order, which is itself part of the contract)
 */

/** The five routes `attome_search::router::route_name` can return. */
export type PredictedRoute = 'exact' | 'phrase' | 'name_lookup' | 'aggregation' | 'hybrid';

/** A prediction, with the rule that produced it — the lab shows both. */
export interface RoutePrediction {
  route: PredictedRoute;
  /** e.g. "Rule 1 - identifier". Rendered next to the route chip. */
  rule: string;
  /** The query after `normalizeAr`, which is what every rule after 2 sees. */
  normalized: string;
}

const TATWEEL = 'ـ';

/** `is_tashkeel`: harakat block, superscript alef, Quranic annotation marks. */
function isTashkeel(code: number): boolean {
  return (
    (code >= 0x064b && code <= 0x065f) || code === 0x0670 || (code >= 0x06d6 && code <= 0x06ed)
  );
}

/** `fold_letter`: the pairs native typists interchange, onto one representative. */
function foldLetter(ch: string): string {
  switch (ch) {
    // Alef with any hamza or madda, and the Quranic wasla, to bare alef.
    case 'آ':
    case 'أ':
    case 'إ':
    case 'ٱ':
      return 'ا';
    // Alef maksura to ya.
    case 'ى':
      return 'ي';
    // Taa marbuta to haa.
    case 'ة':
      return 'ه';
    // Hamza carriers to the bare hamza.
    case 'ؤ':
    case 'ئ':
      return 'ء';
    default:
      return ch;
  }
}

/** `fold_digit`: Arabic-Indic and Eastern Arabic-Indic digits to ASCII. */
function foldDigit(ch: string): string {
  const code = ch.charCodeAt(0);
  if (code >= 0x0660 && code <= 0x0669) return String.fromCharCode(0x30 + (code - 0x0660));
  if (code >= 0x06f0 && code <= 0x06f9) return String.fromCharCode(0x30 + (code - 0x06f0));
  return ch;
}

/**
 * `normalize_ar`, step for step and in the same order — diacritics out first so
 * no fold has to reason about a combining mark, whitespace collapsed last so an
 * earlier removal cannot leave a doubled space behind.
 *
 * Iterates code points (`[...input]`), not UTF-16 units, so a character outside
 * the BMP is never split in half.
 */
export function normalizeAr(input: string): string {
  let out = '';
  for (const ch of input) {
    if (ch === TATWEEL || isTashkeel(ch.charCodeAt(0))) continue;
    out += foldDigit(foldLetter(ch));
  }
  return out.toLowerCase().split(/\s+/).filter(Boolean).join(' ');
}

/** `is_quoted`. */
function isQuoted(s: string): boolean {
  return s.length >= 2 && s.startsWith('"') && s.endsWith('"');
}

const ASCII_DIGIT = /[0-9]/;

/**
 * `looks_like_identifier`: no spaces, and either a digit alongside something
 * that is not a digit, or four-plus digits and nothing else.
 *
 * The digit requirement is what keeps a bare word ("acme") out of the exact
 * route, where it would short-circuit ranking and match no `exact_keys` entry.
 */
function looksLikeIdentifier(normalized: string): boolean {
  if (normalized.includes(' ')) return false;
  const chars = [...normalized];
  const hasDigit = chars.some((c) => ASCII_DIGIT.test(c));
  const hasNonDigit = chars.some((c) => !ASCII_DIGIT.test(c));
  if (hasDigit && hasNonDigit) return true;
  return normalized.length >= 4 && hasDigit && !hasNonDigit;
}

/**
 * `AGGREGATION_MARKERS`. The Arabic entries are already in normalized form (no
 * tashkeel, letters folded), exactly as the Rust constant is — they are matched
 * against the normalized query, never the raw one.
 */
const AGGREGATION_MARKERS = [
  'how many',
  'count of',
  'number of',
  'total of',
  'sum of',
  'average',
  'كم عدد',
  'عدد',
  'مجموع',
  'اجمالي',
  'متوسط',
];

/**
 * The route this query *should* take, per the documented rules.
 *
 * Rule order is load-bearing and matches the backend: quoted beats identifier
 * (a quoted invoice number is a phrase search for that literal string),
 * identifier beats aggregation, aggregation beats name lookup, and name lookup
 * is human-only — an agent that emitted two words composed them as content and
 * must not get prefix semantics by accident of spelling.
 */
export function predictRoute(raw: string, audience: 'human' | 'agent'): RoutePrediction {
  const trimmed = raw.trim();

  if (isQuoted(trimmed)) {
    return { route: 'phrase', rule: 'Rule 2 - quoted', normalized: normalizeAr(trimmed) };
  }

  const normalized = normalizeAr(trimmed);
  if (normalized.length === 0) {
    return { route: 'hybrid', rule: 'Rule 5 - empty after normalization', normalized };
  }

  if (looksLikeIdentifier(normalized)) {
    return { route: 'exact', rule: 'Rule 1 - identifier', normalized };
  }

  if (AGGREGATION_MARKERS.some((m) => normalized.includes(m))) {
    return { route: 'aggregation', rule: 'Rule 4 - arithmetic question', normalized };
  }

  const tokens = normalized.split(' ').filter(Boolean).length;
  if (audience === 'human' && tokens >= 1 && tokens <= 2) {
    return { route: 'name_lookup', rule: 'Rule 3 - one or two name tokens', normalized };
  }

  return { route: 'hybrid', rule: 'Rule 5 - everything else', normalized };
}
