import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { firstValueFrom } from 'rxjs';
import { describe, expect, it } from 'vitest';
import { en } from './en.catalog';
// Spec-only: base's tsconfig.spec.json maps the entry point to its source.
import { KNOWN_OPERATIONS, STEP_UP_LOCAL_FACTORS } from '@attome/base/step-up';
// The Arabic catalog is its own lazily imported entry point (catalogs.ts);
// base's tsconfig.spec.json maps this specifier to its source, not dist.
import { ar } from '@attome/base/i18n-ar';
import { InMemoryTranslocoLoader } from './transloco.loader';

// AUDIT-2026-09-20 finding 4. Two catalog pairs existed: the live TS modules
// and an `i18n/{en,ar}.json` pair that nothing imported. Keys kept being added
// to the dead one — 39 keys across kanban/calendar/timeline, the whole GRC
// control-matrix and policy-list screens, the entity-list filter operators and
// three auth strings resolved to nothing and rendered as their own raw key, in
// both languages, because Transloco's DefaultMissingHandler returns the key.
// The JSON pair is deleted; this test is what stops it coming back.
//
// NGB-5.2 / D-761: this spec covers base's own consumers against base's own
// catalog. The workspace-wide check — every layer's consumers against the
// merged registration of all three layers — is the host's
// src/app/i18n/catalog-coverage.spec.ts.
//
// The required key set is derived from CONSUMERS, never from the catalogs —
// deriving it from a catalog would make the test tautological, which is exactly
// how the gap survived. Keys are then resolved through the real production
// registration path (`InMemoryTranslocoLoader`, the loader `provideTransloco`
// is configured with), not by reading a file.
//
// Known limitation, deliberate: a key chosen by an expression
// (`(isEdit() ? 'a' : 'b') | translate`) is not matched by these patterns, so
// coverage is a floor rather than a ceiling. Widening the regex to catch them
// would start matching string literals that are not keys, and a coverage test
// that cries wolf gets deleted. Prefer a literal key per branch in new code.

/** `process.cwd()` is the angular/ workspace root under `ng test`. */
const ANGULAR_ROOT = resolve(process.cwd());
const SCAN_ROOTS = ['projects/base'];
const SKIP_DIRS = new Set(['node_modules', 'dist', '.angular', 'generated']);

function consumerFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) consumerFiles(full, out);
    else if (/\.(html|ts)$/.test(entry.name) && !entry.name.endsWith('.spec.ts')) out.push(full);
  }
  return out;
}

/** `'a.b' | translate` — the template pipe. */
const PIPE = /'([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'\s*\|\s*translate/g;
/** `lang.translate('a.b')` / `this.lang.translate('a.b', …)` — the TS call. */
const CALL = /\.translate\(\s*'([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'/g;
/**
 * `error.set('a.b')` — a key stored in a signal and rendered later as
 * `{{ errorKey | translate }}`. Restricted to literals whose first segment is
 * already a catalog namespace, so an unrelated dotted string (a route, a MIME
 * type, a css var) cannot masquerade as a missing key. `grc.*.loadError` is
 * the live example, and is invisible to the two patterns above.
 */
const SET = /\.set\(\s*'([a-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'\s*\)/g;

function requiredKeys(namespaces: Set<string>): Map<string, string> {
  const found = new Map<string, string>(); // key -> first call site
  for (const root of SCAN_ROOTS) {
    for (const file of consumerFiles(join(ANGULAR_ROOT, root))) {
      const src = readFileSync(file, 'utf-8');
      const where = relative(ANGULAR_ROOT, file).split('\\').join('/');
      for (const re of [PIPE, CALL, SET]) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(src))) {
          const key = m[1];
          if (re === SET && !namespaces.has(key.split('.')[0])) continue;
          if (!found.has(key)) found.set(key, `${where}:${src.slice(0, m.index).split('\n').length}`);
        }
      }
    }
  }
  return found;
}

const lookup = (catalog: unknown, key: string): unknown =>
  key.split('.').reduce<unknown>(
    (o, part) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[part] : undefined),
    catalog,
  );

function flatten(catalog: Record<string, unknown>, prefix = '', out = new Set<string>()): Set<string> {
  for (const [k, v] of Object.entries(catalog)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v as Record<string, unknown>, key, out);
    else out.add(key);
  }
  return out;
}

describe('i18n catalog coverage', () => {
  it('registers every translation key base asks for, in English and Arabic', async () => {
    // The production path: this is the loader `provideTransloco` is given, so
    // whatever it returns is literally what Transloco resolves against.
    const loader = new InMemoryTranslocoLoader();
    const liveEn = (await firstValueFrom(loader.getTranslation('en'))) as Record<string, unknown>;
    const liveAr = (await firstValueFrom(loader.getTranslation('ar'))) as Record<string, unknown>;

    // …and the other registration path, `LangService` (`setTranslation(en,
    // 'en')` in its constructor, the lazily imported `ar` on first use), must
    // be the same object, not a second copy.
    expect(liveEn).toBe(en);
    expect(liveAr).toBe(ar);

    const required = requiredKeys(new Set(Object.keys(liveEn)));
    expect(required.size, 'the consumer scan found nothing — the walk is broken').toBeGreaterThan(30);

    const missingEn = [...required].filter(([k]) => lookup(liveEn, k) === undefined);
    const missingAr = [...required].filter(([k]) => lookup(liveAr, k) === undefined);

    expect(missingEn.map(([k, at]) => `${k}  (${at})`)).toEqual([]);
    expect(missingAr.map(([k, at]) => `${k}  (${at})`)).toEqual([]);
  }, 20_000);

  // NGB-3.5 — the two dynamic key families the literal scan (PIPE/CALL/SET)
  // cannot see: the prompt picks a factor key from `StepUpLocalFactor` and an
  // operation key from `KNOWN_OPERATIONS`. Both lists are exported by their
  // owners, so adding a factor without its copy fails here rather than
  // rendering a raw key at the step-up prompt.
  it('covers the step-up prompt keys it chooses dynamically (NGB-3.5)', () => {
    const keys = [
      ...STEP_UP_LOCAL_FACTORS.map(f => `stepUp.factor.${f}`),
      ...KNOWN_OPERATIONS.map(op => `stepUp.operation.${op}`),
      'stepUp.operation.default',
    ];
    for (const [name, catalog] of [['en', en], ['ar', ar]] as [string, Record<string, unknown>][]) {
      for (const key of keys) {
        expect(lookup(catalog, key), `${name} lacks ${key}`).toBeTypeOf('string');
      }
    }
  });

  it('keeps the English and Arabic catalogs key-for-key identical', () => {
    const enKeys = flatten(en as Record<string, unknown>);
    const arKeys = flatten(ar as Record<string, unknown>);
    expect([...enKeys].filter(k => !arKeys.has(k)).sort(), 'present in en, missing in ar').toEqual([]);
    expect([...arKeys].filter(k => !enKeys.has(k)).sort(), 'present in ar, missing in en').toEqual([]);
  });
});
