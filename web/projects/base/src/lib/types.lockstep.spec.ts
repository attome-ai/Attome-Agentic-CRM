import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * NGB-2.4. Reads source off disk (like
 * `projects/xrm/core/wire-types-from-codegen.lockstep.spec.ts`) rather than
 * importing the generated document, so it needs no build and its failure names
 * the file and the type.
 *
 * Two directions:
 *
 * 1. A hand-written declaration in `types.ts` whose name is also a generated
 *    schema name must be a `type` alias of `components['schemas'][…]`, never a
 *    second `interface` body. Fourteen types were aliased by NGB-2.4; this is
 *    what stops the fifteenth from being hand-written.
 * 2. The six types that still have no named schema are listed below and must
 *    stay absent from the document — the moment the backend publishes one, this
 *    fails and names it, exactly like attome-types' `SDK_KNOWN_GAPS`.
 */

// `process.cwd()` is the angular/ workspace root under `ng test`.
const ANGULAR_ROOT = process.cwd();
const TYPES_FILE = join(ANGULAR_ROOT, 'projects/base/src/lib/types.ts');
const API_TYPES_FILE = join(ANGULAR_ROOT, 'projects/base/src/lib/generated/api-types.ts');

/** The names NGB-2.4 deliberately leaves hand-written (no named schema yet). */
const NO_NAMED_SCHEMA_YET = [
  'AuthResponse',
  'MfaChallenge',
  'MfaEnrollResponse',
  'MfaPendingConfirmResponse',
  'MfaStatus',
  'MfaRecoveryCodes',
];

/**
 * The generated `ApiComponents['schemas']` key set, by brace-depth counting so
 * a nested field that looks like a top-level entry is never mistaken for one.
 */
let cachedSchemaNames: Set<string> | undefined;

function generatedSchemaNames(): Set<string> {
  if (cachedSchemaNames) return cachedSchemaNames;
  const src = readFileSync(API_TYPES_FILE, 'utf-8');
  const marker = 'schemas: {';
  const start = src.indexOf(marker);
  if (start === -1) throw new Error(`could not find "${marker}" in ${API_TYPES_FILE}`);
  // One linear pass: the depth at the start of each line decides whether an
  // 8-space `Name:` is a top-level schema key. (Re-counting braces from the
  // block start per match was quadratic and timed out under load.)
  const names = new Set<string>();
  const topLevelKey = /^ {8}([A-Za-z0-9_]+):/;
  let depth = 1;
  let lineStart = start + marker.length;
  while (depth > 0 && lineStart < src.length) {
    const nl = src.indexOf('\n', lineStart);
    const lineEnd = nl === -1 ? src.length : nl;
    const line = src.slice(lineStart, lineEnd);
    if (depth === 1 && lineStart > start + marker.length) {
      const m = topLevelKey.exec(line);
      if (m) names.add(m[1]);
    }
    for (const c of line) {
      if (c === '{') depth++;
      else if (c === '}') depth--;
      if (depth === 0) break;
    }
    lineStart = lineEnd + 1;
  }
  cachedSchemaNames = names;
  return names;
}

describe('@attome/base wire types vs the generated document (NGB-2.4)', () => {
  it('never hand-writes a type that the generated document already names', () => {
    const schemaNames = generatedSchemaNames();
    expect(schemaNames.size).toBeGreaterThan(100); // sanity: the extraction found the block

    const src = readFileSync(TYPES_FILE, 'utf-8');
    const violations: string[] = [];
    // `export interface <Name>` / `export interface <Name> { … }`.
    const interfacePattern = /export interface ([A-Za-z0-9_]+)/g;
    let m: RegExpExecArray | null;
    while ((m = interfacePattern.exec(src))) {
      if (schemaNames.has(m[1])) violations.push(m[1]);
    }

    expect(violations, 'alias these to components[\'schemas\'][…] instead of hand-writing them').toEqual([]);
  });

  it('still has no named schema for the types NGB-2.4 left hand-written', () => {
    const schemaNames = generatedSchemaNames();
    const arrived = NO_NAMED_SCHEMA_YET.filter(name => schemaNames.has(name));
    expect(
      arrived,
      'the backend now publishes a schema for these; alias them to components[\'schemas\'][…] and drop them from NO_NAMED_SCHEMA_YET',
    ).toEqual([]);
  });

  it('the fourteen aliased types really resolve through components[\'schemas\']', () => {
    const src = readFileSync(TYPES_FILE, 'utf-8');
    const aliased = [
      'SessionInfo', 'GoogleAuthRequest', 'RegisterRequest', 'RegistrationConfigInfo',
      'LoginRequest', 'OidcProviderInfo', 'IdentityLinkInfo', 'GoogleConfigInfo',
      'MfaVerifyBody', 'MfaPendingEnrollBody', 'ResetRequestBody', 'ResetConfirmBody',
      'VerifyEmailConfirmBody', 'Ack',
    ];
    const missing = aliased.filter(name => !new RegExp(
      `export type ${name} =[\\s\\S]*?components\\['schemas'\\]\\['${name}'\\]`,
    ).test(src));
    expect(missing).toEqual([]);
  });
});
