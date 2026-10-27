import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * C-26 proof: a hand-written `...Item` interface in a `core/**` service file
 * must not duplicate a generated OpenAPI schema of the same name — that
 * duplication is exactly the drift this change closes (`admin.service.ts`'s
 * `EntityMeta`/`AttributeMeta` missing fields, `security-admin.service.ts`'s
 * 39 hand-written twins of generated types, M01-core.md §7 C-26).
 *
 * Reads source off disk directly (like `field-types.lockstep.spec.ts`
 * alongside this one) rather than importing the service modules or the
 * generated `api-types.ts` through `@attome/base` — this spec's whole point
 * is to catch drift in files nothing else here imports, and reading raw text
 * means it needs neither `dist/base` nor `dist/xrm` built first.
 */

// process.cwd() is the angular/ workspace root when `ng test xrm` runs.
const ANGULAR_ROOT = process.cwd();
const CORE_DIR = join(ANGULAR_ROOT, 'projects/xrm/core');
const API_TYPES_FILE = join(ANGULAR_ROOT, 'projects/base/src/lib/generated/api-types.ts');

function listServiceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listServiceFiles(full));
    else if (entry.isFile() && entry.name.endsWith('.service.ts')) out.push(full);
  }
  return out;
}

/**
 * The generated `ApiComponents['schemas']` key set — every schema name the
 * backend's OpenAPI document actually defines. Extracted by brace-depth
 * counting (not a flat line regex) so a nested field that happens to look
 * like a top-level entry (e.g. a schema's own `Name: { ... }` sub-object)
 * is never mistaken for one of the ~590 real schema names.
 */
function generatedSchemaNames(): Set<string> {
  const src = readFileSync(API_TYPES_FILE, 'utf-8');
  const marker = 'schemas: {';
  const start = src.indexOf(marker);
  if (start === -1) {
    throw new Error(`could not find "${marker}" in ${API_TYPES_FILE}`);
  }
  let i = start + marker.length;
  let depth = 1;
  const chars: string[] = [];
  while (depth > 0 && i < src.length) {
    const ch = src[i];
    if (ch === '{') depth++;
    else if (ch === '}') depth--;
    chars.push(ch);
    i++;
  }
  const block = chars.join('');
  const names = new Set<string>();
  const topLevelKey = /\n {8}([A-Za-z0-9_]+):/g;
  let m: RegExpExecArray | null;
  // The depth is carried forward from one match to the next, so the block
  // is walked once (rescanning the prefix per key was quadratic and made
  // this the suite's slowest test as api-types.ts grew).
  let d = 0;
  let scanned = 0;
  while ((m = topLevelKey.exec(block))) {
    for (let i = scanned; i < m.index; i++) {
      const c = block[i];
      if (c === '{') d++;
      else if (c === '}') d--;
    }
    scanned = m.index;
    // At depth 0 the key is a schema name, not a field nested inside one
    // schema's own object type.
    if (d === 0) names.add(m[1]);
  }
  return names;
}

describe('hand-written *Item interfaces vs generated schemas (C-26)', () => {
  it('declares no core/**/*.service.ts interface named "...Item" that duplicates a generated schema', () => {
    const schemaNames = generatedSchemaNames();
    expect(schemaNames.size).toBeGreaterThan(100); // sanity: the extraction actually found the block

    const violations: { file: string; name: string }[] = [];
    const interfacePattern = /export interface (\w*Item)\b/g;

    for (const file of listServiceFiles(CORE_DIR)) {
      const content = readFileSync(file, 'utf-8');
      let match: RegExpExecArray | null;
      while ((match = interfacePattern.exec(content))) {
        const name = match[1];
        if (schemaNames.has(name)) {
          violations.push({ file: relative(ANGULAR_ROOT, file), name });
        }
      }
    }

    expect(violations).toEqual([]);
    // 20s, not vitest's default 5s: this test synchronously reads the
    // ~48k-line generated api-types.ts, character-walks its schema block
    // (an O(n^2) prefix rescan per key), then globs and regexes every
    // core/**/*.service.ts. It is inherently one of the slowest tests in
    // the suite and its cost grows with the generated document, so under
    // the default budget it fails from suite load rather than from a real
    // violation - adding any two spec files elsewhere was enough to trip it.
  }, 20_000);
});
