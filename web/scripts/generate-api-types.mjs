// Regenerates the checked-in OpenAPI document and the TypeScript types derived
// from it (P-api-contract Phase 2).
//
//   npm run generate:api                         # rebuild both artifacts
//   npm run generate:api -- --features a,b       # ...with optional cargo features built in
//   npm run generate:api -- --spec <path>        # reuse an already-printed document
//   OPENAPI_FEATURES=a,b npm run generate:api    # same as --features, via env
//
// Two artifacts, both committed, both generated — never hand-edit either:
//   openapi.json                                     (repo root)
//   projects/base/src/lib/generated/api-types.ts
//
// Committing them is what makes drift reviewable: a backend response-shape
// change shows up as a diff in the commit that caused it. Nothing re-runs this
// for you — run it yourself after any route or wire-type change, and confirm
// `git diff --exit-code` is clean before committing. The document comes from
// `attome serve --print-openapi`, which is pure in-process schema generation — no
// database, no config file, no listener, no live authenticated server.
//
import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

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

if (specArg >= 0) {
  // An already-printed document is taken as-is: whoever printed it chose the
  // feature set, and this is the path a container-built document arrives by.
  const from = resolve(args[specArg + 1]);
  writeFileSync(SPEC, readFileSync(from));
  console.log(`openapi.json <- ${from}`);
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

  // Normalise to LF and a trailing newline so the committed file is stable
  // across platforms — otherwise a regenerate-and-diff shows line-ending noise.
  const pretty = `${JSON.stringify(doc, null, 2)}\n`;
  writeFileSync(SPEC, pretty, { encoding: 'utf8' });
  console.log(
    `openapi.json <- ${Object.keys(doc.paths).length} paths` +
      (features.length ? ` (features: ${features.join(',')})` : ''),
  );
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
