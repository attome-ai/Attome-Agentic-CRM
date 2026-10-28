// Regenerates the checked-in OpenAPI document and the TypeScript types derived
// from it (P-api-contract Phase 2).
//
//   npm run generate:api                         # rebuild both artifacts
//   npm run generate:api -- --features a,b       # ...with optional cargo features built in
//   npm run generate:api -- --spec <path>        # reuse an already-printed document
//   OPENAPI_FEATURES=a,b npm run generate:api    # same as --features, via env
//   npm run generate:api -- --examples <dir>     # examples from another directory
//
// S2-T10: request and response examples captured by integration tests
// (`ATTOME_CAPTURE_EXAMPLES`, attome-testkit's `examples`) and committed under
// docs/api/examples are set on the matching operations every time, so the
// document keeps them whoever regenerates it.
//
// Two artifacts, both committed, both generated — never hand-edit either:
//   openapi.json                                     (repo root)
//   projects/base/src/lib/generated/api-types.ts
// and beside them openapi.ar.json (S2-T11), openapi/<module>.json and
// docs/api/openapi-quality.json (S2-T15, openapi-split.mjs).
//
// Committing them is what makes drift reviewable: a backend response-shape
// change shows up as a diff in the commit that caused it. Nothing re-runs this
// for you — run it yourself after any route or wire-type change, and confirm
// `git diff --exit-code` is clean before committing. The document comes from
// `attome serve --print-openapi`, which is pure in-process schema generation — no
// database, no config file, no listener, no live authenticated server.
//
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { qualityLines, qualityReport, splitByModule } from './openapi-split.mjs';

const ANGULAR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = resolve(ANGULAR, '..');
const SPEC = join(ROOT, 'openapi.json');
const OUT = join(ANGULAR, 'projects', 'base', 'src', 'lib', 'generated', 'api-types.ts');
// M68 Phase 1 — the SDK ships its own copy of the generated wire types rather
// than importing @attome/base's (which would make a third-party npm package
// depend on our internal Angular library and its @angular/* peer deps for a
// type-only import). Same source document, same openapi-typescript run,
// written to two places so both stay committed and both regenerate together.
const OUT_SDK = join(ANGULAR, 'projects', 'sdk', 'src', 'lib', 'generated', 'api-types.ts');

const args = process.argv.slice(2);
const specArg = args.indexOf('--spec');
const examplesArg = args.indexOf('--examples');
const EXAMPLES = examplesArg >= 0 ? resolve(args[examplesArg + 1]) : join(ROOT, 'docs', 'api', 'examples');

/**
 * Cargo features for the `--print-openapi` build: `--features a,b`,
 * `--features=a,b`, and/or OPENAPI_FEATURES=a,b (unioned, de-duplicated).
 * Empty by default — the plain dev build, same as `cargo run`.
 */
function requestedFeatures() {
  const raw = [];
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--features') raw.push(args[i + 1] ?? '');
    else if (args[i].startsWith('--features=')) raw.push(args[i].slice('--features='.length));
  }
  raw.push(process.env.OPENAPI_FEATURES ?? '');
  return [...new Set(raw.join(',').split(',').map((f) => f.trim()).filter(Boolean))];
}

function run(cmd, argv, opts = {}) {
  const res = spawnSync(cmd, argv, { stdio: ['ignore', 'pipe', 'inherit'], ...opts });
  if (res.error) throw res.error;
  if (res.status !== 0) {
    console.error(`\n${cmd} ${argv.join(' ')} exited with ${res.status}`);
    process.exit(res.status ?? 1);
  }
  return res.stdout;
}

/**
 * utoipa stores an operation's `x-*` extensions in a HashMap, so an operation
 * with more than one (a deprecated route: x-audit, x-sunset, x-replacement)
 * serialises them in a different order on each run. Re-append them sorted so
 * the committed document only changes when its content does.
 */
function sortOperationExtensions(doc) {
  for (const item of Object.values(doc.paths ?? {})) {
    for (const op of Object.values(item)) {
      if (!op || typeof op !== 'object' || Array.isArray(op)) continue;
      const keys = Object.keys(op).filter((k) => k.startsWith('x-')).sort();
      for (const k of keys) {
        const v = op[k];
        delete op[k];
        op[k] = v;
      }
    }
  }
}

/** The captured examples in `dir`, or none when it does not exist. */
function readExamples(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(dir, f), 'utf8')));
}

/** A path template as a matcher: `{x}` is one segment. */
function templateMatcher(template) {
  const pattern = template
    .split('/')
    .map((seg) => (/^\{[^}]+\}$/.test(seg) ? '[^/]+' : seg.replace(/[.*+?^$()|[\]\\]/g, '\\$&')))
    .join('/');
  const literal = template.split('/').filter((s) => s && !s.startsWith('{')).length;
  return { template, literal, re: new RegExp(`^${pattern}$`) };
}

/**
 * Sets each example on its operation: the template that matches the captured
 * path with the most literal segments wins (`/calendars/packs` over
 * `/calendars/{id}`), and the first example of an operation and status wins.
 * Returns how many were set.
 */
function applyExamples(doc, examples) {
  const matchers = Object.keys(doc.paths ?? {}).map(templateMatcher);
  const seen = new Set();
  let set = 0;
  for (const ex of examples) {
    const path = String(ex.uri ?? '').split('?')[0];
    const method = String(ex.method ?? '').toLowerCase();
    const hits = matchers.filter((m) => m.re.test(path)).sort((a, b) => b.literal - a.literal);
    const op = hits.length ? doc.paths[hits[0].template]?.[method] : undefined;
    if (!op) continue;
    const key = `${method} ${hits[0].template} ${ex.status}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const reqJson = op.requestBody?.content?.['application/json'];
    if (reqJson && ex.request != null && reqJson.example === undefined) reqJson.example = ex.request;
    const resJson = op.responses?.[String(ex.status)]?.content?.['application/json'];
    if (resJson && ex.response != null) {
      resJson.example = ex.response;
      set += 1;
    }
  }
  return set;
}

const examples = readExamples(EXAMPLES);

if (specArg >= 0) {
  // An already-printed document is taken as-is: whoever printed it chose the
  // feature set, and this is the path a container-built document arrives by.
  const from = resolve(args[specArg + 1]);
  if (examples.length) {
    const doc = JSON.parse(readFileSync(from, 'utf8'));
    const n = applyExamples(doc, examples);
    writeFileSync(SPEC, `${JSON.stringify(doc, null, 2)}\n`, { encoding: 'utf8' });
    console.log(`openapi.json <- ${from} (${n} examples)`);
  } else {
    writeFileSync(SPEC, readFileSync(from));
    console.log(`openapi.json <- ${from}`);
  }
} else {
  const features = requestedFeatures();
  const cargoArgs = ['run', '-q', '-p', 'attome', '--bin', 'attome'];
  if (features.length) cargoArgs.push('--features', features.join(','));
  cargoArgs.push('--', 'serve', '--print-openapi');
  console.log(`cargo ${cargoArgs.join(' ')}`);
  const json = run('cargo', cargoArgs, {
    cwd: ROOT,
    maxBuffer: 64 * 1024 * 1024,
  });
  const doc = JSON.parse(json);
  sortOperationExtensions(doc);
  const exampleCount = applyExamples(doc, examples);

  // Normalise to LF and a trailing newline so the committed file is stable
  // across platforms — otherwise a regenerate-and-diff shows line-ending noise.
  const pretty = `${JSON.stringify(doc, null, 2)}\n`;
  writeFileSync(SPEC, pretty, { encoding: 'utf8' });
  console.log(
    `openapi.json <- ${Object.keys(doc.paths).length} paths` +
      (features.length ? ` (features: ${features.join(',')})` : '') +
      (exampleCount ? `, ${exampleCount} examples` : ''),
  );
}

// S2-T11: the Arabic parallel document, from the translation catalog: the
// summaries, descriptions and tag descriptions it has, nothing else.
const AR_CATALOG = join(ROOT, 'docs', 'api', 'openapi-ar.catalog.json');
const SPEC_AR = join(ROOT, 'openapi.ar.json');
let arabicTranslated = 0;
if (existsSync(AR_CATALOG)) {
  const catalog = JSON.parse(readFileSync(AR_CATALOG, 'utf8'));
  const doc = JSON.parse(readFileSync(SPEC, 'utf8'));
  let translated = 0;
  for (const item of Object.values(doc.paths ?? {})) {
    for (const op of Object.values(item)) {
      const text = op && typeof op === 'object' ? catalog.operations?.[op.operationId] : undefined;
      if (!text) continue;
      if (text.summary) op.summary = text.summary;
      if (text.description) op.description = text.description;
      translated += 1;
    }
  }
  for (const tag of doc.tags ?? []) {
    if (catalog.tags?.[tag.name]) tag.description = catalog.tags[tag.name];
  }
  writeFileSync(SPEC_AR, `${JSON.stringify(doc, null, 2)}\n`, { encoding: 'utf8' });
  console.log(`openapi.ar.json <- ${translated} operations in Arabic`);
  arabicTranslated = translated;
}

// S2-T15: one document per module under openapi/, and the quality report.
// A module no longer in the document loses its file.
{
  const doc = JSON.parse(readFileSync(SPEC, 'utf8'));
  const dir = join(ROOT, 'openapi');
  mkdirSync(dir, { recursive: true });
  const parts = splitByModule(doc);
  for (const name of readdirSync(dir)) {
    if (name.endsWith('.json') && !parts.has(name.slice(0, -'.json'.length))) rmSync(join(dir, name));
  }
  for (const [module, part] of parts) {
    writeFileSync(join(dir, `${module}.json`), `${JSON.stringify(part, null, 2)}\n`, { encoding: 'utf8' });
  }
  console.log(`openapi/ <- ${parts.size} module documents`);
  const baseline = join(ROOT, 'crates', 'apps', 'attome', 'tests', 'openapi_lint_baseline.json');
  const lintBaselineEntries = existsSync(baseline) ? JSON.parse(readFileSync(baseline, 'utf8')).length : 0;
  const report = qualityReport(doc, { arabicTranslated, lintBaselineEntries });
  writeFileSync(join(ROOT, 'docs', 'api', 'openapi-quality.json'), `${JSON.stringify(report, null, 2)}\n`, {
    encoding: 'utf8',
  });
  for (const line of qualityLines(report)) console.log(line);
}

mkdirSync(dirname(OUT), { recursive: true });
// Invoked through `node <cli.js>` rather than `npx openapi-typescript`: it uses
// the version pinned in package-lock.json instead of whatever npx resolves, and
// it avoids spawning a `.cmd` shim (EINVAL under Node's spawnSync on Windows).
const cli = join(ANGULAR, 'node_modules', 'openapi-typescript', 'bin', 'cli.js');
const types = run(process.execPath, [cli, SPEC], {
  cwd: ANGULAR,
  maxBuffer: 64 * 1024 * 1024,
}).toString('utf8');

const banner = [
  '/* eslint-disable */',
  '// GENERATED — do not edit. Run `npm run generate:api` from angular/.',
  '// Source of truth: the `#[utoipa::path]` annotations on the Rust handlers',
  '// (P-api-contract Phase 1/2). Nothing re-runs this; run `npm run generate:api` and commit.',
  '',
].join('\n');

const body = banner + types.replace(/\r\n/g, '\n');
writeFileSync(OUT, body, { encoding: 'utf8' });
console.log(`api-types.ts <- ${OUT}`);

mkdirSync(dirname(OUT_SDK), { recursive: true });
writeFileSync(OUT_SDK, body, { encoding: 'utf8' });
console.log(`api-types.ts <- ${OUT_SDK}`);
