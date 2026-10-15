import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { TestBed } from '@angular/core/testing';
import { TranslocoService } from '@jsverse/transloco';
import { ATTOME_CONFIG, LangService, provideAttomeI18n } from '@attome/base';
import { provideXrmI18n, xrmEn } from '@attome/xrm/core/i18n';
import { xrmAr } from '@attome/xrm/core/i18n-ar';
import { describe, expect, it } from 'vitest';
import { hostAr } from './ar.catalog';
import { hostEn } from './en.catalog';
import { provideHostI18n } from './provide-host-i18n';

// NGB-5.2 / D-761 — each layer owns its catalog, so the only place every key
// a consumer asks for can be checked is where all three layers are registered
// together: here, through the production path (`LangService` merging each
// layer into the one Transloco registration). Base checks its own consumers
// against its own catalog in projects/base/src/lib/i18n/catalog-coverage.spec.ts.

/** `process.cwd()` is the angular/ workspace root under `ng test`. */
const ANGULAR_ROOT = resolve(process.cwd());
const SCAN_ROOTS = ['projects', 'src'];
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

// Same three patterns, and the same known limits, as base's coverage spec.
const PIPE = /'([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'\s*\|\s*translate/g;
const CALL = /\.translate\(\s*'([A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'/g;
const SET = /\.set\(\s*'([a-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+)'\s*\)/g;

function requiredKeys(namespaces: Set<string>): Map<string, string> {
  const found = new Map<string, string>();
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

function flatten(catalog: Record<string, unknown>, prefix = '', out = new Set<string>()): Set<string> {
  for (const [k, v] of Object.entries(catalog)) {
    const key = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v as Record<string, unknown>, key, out);
    else out.add(key);
  }
  return out;
}

/** B20-T2: the string at a dotted key, or undefined. */
function valueAt(catalog: Record<string, unknown>, key: string): unknown {
  return key.split('.').reduce<unknown>(
    (node, part) => (node && typeof node === 'object' ? (node as Record<string, unknown>)[part] : undefined),
    catalog,
  );
}

/** B20-T2: the `{name}` placeholders a message uses (ICU arguments included). */
function placeholders(message: unknown): string[] {
  if (typeof message !== 'string') return [];
  return [...new Set([...message.matchAll(/\{\s*([A-Za-z_]\w*)\s*[,}]/g)].map(m => m[1]))].sort();
}

const resolves = (flat: Record<string, unknown>, key: string): boolean =>
  flat[key] !== undefined || Object.keys(flat).some(k => k.startsWith(`${key}.`));

describe('i18n catalog coverage — all layers', () => {
  it('registers every key any layer asks for, in English and Arabic', async () => {
    TestBed.configureTestingModule({
      providers: [
        { provide: ATTOME_CONFIG, useValue: { apiUrl: 'http://localhost:7865' } },
        provideAttomeI18n(),
        provideXrmI18n(),
        provideHostI18n(),
      ],
    });
    const lang = TestBed.inject(LangService);
    await lang.set('ar');
    const transloco = TestBed.inject(TranslocoService);
    const liveEn = transloco.getTranslation('en') as Record<string, unknown>;
    const liveAr = transloco.getTranslation('ar') as Record<string, unknown>;

    const namespaces = new Set(Object.keys(liveEn).map(k => k.split('.')[0]));
    const required = requiredKeys(namespaces);
    expect(required.size, 'the consumer scan found nothing — the walk is broken').toBeGreaterThan(1000);

    const missingEn = [...required].filter(([k]) => !resolves(liveEn, k));
    const missingAr = [...required].filter(([k]) => !resolves(liveAr, k));
    expect(missingEn.map(([k, at]) => `${k}  (${at})`)).toEqual([]);
    expect(missingAr.map(([k, at]) => `${k}  (${at})`)).toEqual([]);
  }, 30_000);

  it('keeps each layer\'s English and Arabic catalogs key-for-key identical', () => {
    for (const [name, en, ar] of [['xrm', xrmEn, xrmAr], ['host', hostEn, hostAr]] as const) {
      const enKeys = flatten(en as Record<string, unknown>);
      const arKeys = flatten(ar as Record<string, unknown>);
      expect([...enKeys].filter(k => !arKeys.has(k)).sort(), `${name}: present in en, missing in ar`).toEqual([]);
      expect([...arKeys].filter(k => !enKeys.has(k)).sort(), `${name}: present in ar, missing in en`).toEqual([]);
    }
  });

  it('gives each English message and its Arabic one the same placeholders (B20-T2)', () => {
    const mismatched: string[] = [];
    for (const [name, en, ar] of [['xrm', xrmEn, xrmAr], ['host', hostEn, hostAr]] as const) {
      for (const key of flatten(en as Record<string, unknown>)) {
        const want = placeholders(valueAt(en as Record<string, unknown>, key));
        const got = placeholders(valueAt(ar as Record<string, unknown>, key));
        if (want.join(',') !== got.join(',')) mismatched.push(`${name}:${key} en {${want}} ar {${got}}`);
      }
    }
    expect(mismatched).toEqual([]);
  });

  it('gives every namespace exactly one owning layer', () => {
    const shared = Object.keys(xrmEn).filter(ns => ns in hostEn);
    expect(shared).toEqual([]);
  });
});
