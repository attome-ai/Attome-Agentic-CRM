#!/usr/bin/env node
/**
 * Caps the size of individual lazy chunks (D-314).
 *
 * Angular's own budgets cannot express this. `initial` covers only the eager
 * bundle, and `any` applies to every emitted file — including `main`, which at
 * ~391 kB is far larger than any lazy chunk. So the `any` cap has to sit above
 * `main` to let the build pass, which leaves it useless as a lazy-chunk gate:
 * after D-314 took the biggest lazy chunk from 448.64 kB down to 183.77 kB,
 * that chunk could grow all the way back to 448 kB without tripping the 500 kB
 * `any` budget. There is no "lazy chunk" budget type to use instead.
 *
 * This is that gate. It reads the built output rather than a stats file, so it
 * needs nothing beyond `npm run build` having run.
 *
 *   node scripts/chunk-budget.mjs                 # check against MAX_LAZY_CHUNK
 *   node scripts/chunk-budget.mjs --list          # print every chunk, largest first
 *
 * Raising MAX_LAZY_CHUNK is a deliberate act: check first whether a
 * cross-entry-point import re-collapsed the split (see D-314's rule that a
 * `@attome/xrm` entry point imports a sibling's `/data` entry point, never its
 * component barrel) — that is what produced the 448 kB chunk in the first
 * place, and it looks exactly like ordinary growth in this report.
 */
import { readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';

const BROWSER_DIR = 'dist/attome-website/browser';

// Measured 2026-08-23: largest lazy chunk 263.85 kB — the shared
// `@attome/xrm/core/entity` widget chunk (FieldInputComponent, EntityListComponent,
// RelatedGridComponent, the Communications/Documents/Notes/TeamRoles panels)
// that every per-entity form composes, now that every built-in entity has
// its own bespoke form (~30 registered entities, each lazy-loaded on first
// visit via EntityRouteRegistry.ensureLoaded — see that class's doc comment).
// Verified before raising this, per the note below: `--list` plus a
// selector-string scan of the chunk showed only that shared widget set, no
// leaked dispatcher/other-module content — this is legitimate shared code,
// not a re-collapse. The cap is that measurement plus headroom for ordinary
// growth, still well under the 448.64 kB that D-314 originally removed, so a
// real re-collapse still fails here instead of shipping.
//
// Re-measured 2026-08-25: 303.03 kB after FE-6 put `@angular/cdk/scrolling`
// (CdkVirtualScrollViewport + FixedSizeVirtualScrollStrategy) into the
// document-folder browser, plus PROD-12's bulk-edit dialog in EntityList. Same
// verification, same result — the selector scan still shows only the widget
// set above (no workflow/webcrawl/dispatcher content), so the growth is a real
// dependency, not a re-collapse. Cap moved to that measurement plus headroom.
const MAX_LAZY_CHUNK = 360 * 1024;

const kb = (n) => `${(n / 1024).toFixed(2)} kB`;

let files;
try {
  files = await readdir(BROWSER_DIR);
} catch {
  console.error(`chunk-budget: ${BROWSER_DIR} not found — run \`npm run build\` first.`);
  process.exit(2);
}

// `main-*.js` is the eager entry point, governed by the `initial` budget in
// angular.json; polyfills likewise. Everything else `.js` is a lazy chunk.
const lazy = [];
for (const name of files) {
  if (!name.endsWith('.js')) continue;
  if (/^(main|polyfills)-/.test(name)) continue;
  const { size } = await stat(join(BROWSER_DIR, name));
  lazy.push({ name, size });
}
lazy.sort((a, b) => b.size - a.size);

if (process.argv.includes('--list')) {
  for (const c of lazy) console.log(`${kb(c.size).padStart(10)}  ${c.name}`);
  process.exit(0);
}

const over = lazy.filter((c) => c.size > MAX_LAZY_CHUNK);
if (over.length) {
  console.error(`chunk-budget: ${over.length} lazy chunk(s) exceed ${kb(MAX_LAZY_CHUNK)}:`);
  for (const c of over) console.error(`  ${c.name}  ${kb(c.size)}`);
  console.error(
    '\nBefore raising the cap, check whether a cross-entry-point import re-collapsed\n' +
    "the @attome/xrm split (D-314): a sibling's component barrel imported for a service\n" +
    'pulls that whole entry point in. `node scripts/chunk-budget.mjs --list` shows the\n' +
    'full picture.',
  );
  process.exit(1);
}

console.log(
  `chunk-budget: ${lazy.length} lazy chunks, largest ${kb(lazy[0]?.size ?? 0)} ` +
  `(cap ${kb(MAX_LAZY_CHUNK)}).`,
);
