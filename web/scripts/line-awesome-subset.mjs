// Regenerates the checked-in Line Awesome subset — the icon CSS and the font
// binary, both cut down to the icons this workspace actually references.
//
//   npm run generate:icons              # rebuild both artifacts
//   npm run generate:icons -- --check   # fail if the committed ones are stale
//
// Two artifacts, both committed, both generated — never hand-edit either:
//   src/styles/line-awesome-subset.css
//   src/styles/fonts/la-<weight>-subset.woff2
//
// Why this exists: `line-awesome.min.css` is 89,729 bytes defining 1,659 icon
// rules, and it is loaded eagerly (angular.json `styles`), so it was ~99% of the
// initial styles bundle. This workspace uses 91 of those icons and only the
// `las` (solid) weight — zero `lar`, zero `lab`. The upstream CSS also declares
// @font-face `src` lists covering eot/svg/ttf/woff/woff2 for all three weights,
// which made the build emit all 15 font binaries (~3.1 MB) whether or not a
// glyph from them could ever render.
//
// Committing the output is what makes drift reviewable, and it keeps the
// subsetter off the normal build path: `ng build` just reads a .css and a
// .woff2. Only regeneration needs `subset-font`. Same contract as
// generate-api-types.mjs — re-run this with --check yourself; nothing else does.
//
// Adding an icon to a template is enough; re-run this and commit the result.
import { mkdirSync, readFileSync, readdirSync, writeFileSync, statSync } from 'node:fs';
import { dirname, join, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import subsetFont from 'subset-font';

const ANGULAR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const LA = join(ANGULAR, 'node_modules', 'line-awesome', 'dist', 'line-awesome');
const SRC_CSS = join(LA, 'css', 'line-awesome.min.css');
const OUT_DIR = join(ANGULAR, 'src', 'styles');
const OUT_CSS = join(OUT_DIR, 'line-awesome-subset.css');
const FONT_DIR = join(OUT_DIR, 'fonts');

// Where component/template source lives. Anything outside these trees cannot
// reference an icon class that reaches the browser.
const SCAN_ROOTS = [join(ANGULAR, 'projects'), join(ANGULAR, 'src')];
const SCAN_EXT = new Set(['.ts', '.html', '.css']);

// The three weight classes upstream defines, mapped to their font file stem and
// the @font-face identity the icon rules resolve against.
const WEIGHTS = {
  las: { file: 'la-solid-900',  family: 'Line Awesome Free',   weight: 900 },
  lar: { file: 'la-regular-400', family: 'Line Awesome Free',  weight: 400 },
  lab: { file: 'la-brands-400',  family: 'Line Awesome Brands', weight: 400 },
};

const check = process.argv.slice(2).includes('--check');

function walk(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === 'dist' || e.name.startsWith('.')) continue;
      walk(p, out);
    } else if (SCAN_EXT.has(extname(e.name))) {
      out.push(p);
    }
  }
  return out;
}

const css = readFileSync(SRC_CSS, 'utf8');

// Every icon rule upstream defines: `.la-adjust:before{content:"\f042"}`.
// Selectors are never grouped in this file (verified against 1,659 rules), so a
// single-selector match is exhaustive rather than a convenient approximation.
const iconRule = /\.(la-[a-z0-9-]+):before\{content:"\\([0-9a-f]+)"\}/g;
const defined = new Map();
for (const [, name, code] of css.matchAll(iconRule)) defined.set(name, code);

// Scan for both the icon names and the weight classes. A token that is not a
// defined icon (`la-spin`, `la-fw`, a project's own `la-`-prefixed class) is
// ignored here — the non-icon parts of the upstream CSS are kept wholesale
// below, so those keep working without being enumerated.
// The generated CSS itself lives under src/ and names every icon it emits (and,
// via the aliases, plenty it does not). Scanning it would ratchet the set upward
// on every run — 91 icons became 419 on the second pass before this exclusion.
const files = SCAN_ROOTS.flatMap(r => walk(r)).filter(f => f !== OUT_CSS);
const usedIcons = new Set();
const usedWeights = new Set();
for (const f of files) {
  const text = readFileSync(f, 'utf8');
  for (const [, tok] of text.matchAll(/\b(la-[a-z0-9-]+)\b/g)) {
    if (defined.has(tok)) usedIcons.add(tok);
  }
  for (const [, w] of text.matchAll(/\b(las|lar|lab)\b(?=\s|["'`]|\s*la-)/g)) {
    if (WEIGHTS[w]) usedWeights.add(w);
  }
}
if (usedWeights.size === 0) usedWeights.add('las');

// Font Awesome compat aliases: `.la.la-youtube-square{font-family:'Line Awesome
// Brands';font-weight:400}`, which route the *bare* `.la` form (`class="la
// la-x"`) to the right family. 330 of them, 22,386 bytes — the single largest
// block after the icon rules. Kept only for icons this workspace uses, so
// writing `la la-cog` still resolves, without carrying 330 rules for icons that
// are not in the font any more.
const aliasRule = /\.la\.(la-[a-z0-9-]+)\{[^}]*\}/g;
const aliases = [...css.matchAll(aliasRule)]
  .filter(([, name]) => usedIcons.has(name))
  .map(([rule]) => rule)
  .sort()
  .join('\n');

// Keep every remaining non-icon rule verbatim — the base `.la/.las{...}`
// declarations, the sizing/spin/stack/pull utilities, `.sr-only`, and their
// keyframes. That is ~1.5 kB total, and keeping it wholesale means a template
// can start using `la-spin` or `la-2x` without this script needing to know
// about it. Only the icon rules, the aliases and the @font-face blocks are
// rewritten.
let base = css
  .replace(iconRule, '')
  .replace(aliasRule, '')
  .replace(/@font-face\{[^}]*\}/g, '');

const sortedIcons = [...usedIcons].sort();
const sortedWeights = [...usedWeights].sort();
// The checked-in font filename is intentionally stable, but dev servers serve
// it at that stable URL without Angular's production content hash. Give each
// glyph set a cache key so a browser cannot keep using an older subset after a
// newly referenced icon is added.
const fontCacheKey = createHash('sha256')
  .update(`${sortedWeights.join(',')}\n${sortedIcons.join('\n')}`)
  .digest('hex')
  .slice(0, 12);

const faces = sortedWeights.map(w => {
  const { file, family, weight } = WEIGHTS[w];
  // woff2 only. Every browser this Angular 22 build targets supports it; the
  // eot/svg/ttf/woff entries upstream exist for IE and pre-2016 Safari and were
  // ~1.47 MB of emitted assets for the solid weight alone.
  return `@font-face{font-family:'${family}';font-style:normal;font-weight:${weight};`
    + `font-display:swap;src:url(./fonts/${file}-subset.woff2?v=${fontCacheKey}) format("woff2")}`;
}).join('\n');

const rules = sortedIcons.map(n => `.${n}:before{content:"\\${defined.get(n)}"}`).join('\n');

const out = [
  '/* GENERATED — do not edit. Run `npm run generate:icons` from angular/. */',
  `/* ${sortedIcons.length} of ${defined.size} Line Awesome icons; weights: ${sortedWeights.join(', ')}. */`,
  '/* Source of truth: the la-* classes referenced under projects/ and src/. */',
  faces,
  base.trim(),
  rules,
  aliases,
  '',
].join('\n');

// Subset each used weight's font to exactly the codepoints its icon rules need.
// Private-use codepoints, so `text` is built from the escapes themselves.
const fonts = new Map();
for (const w of sortedWeights) {
  const { file } = WEIGHTS[w];
  const text = sortedIcons.map(n => String.fromCodePoint(parseInt(defined.get(n), 16))).join('');
  const src = readFileSync(join(LA, 'fonts', `${file}.woff2`));
  fonts.set(file, await subsetFont(src, text, { targetFormat: 'woff2' }));
}

function stale(path, buf) {
  try { return !readFileSync(path).equals(Buffer.isBuffer(buf) ? buf : Buffer.from(buf, 'utf8')); }
  catch { return true; }
}

if (check) {
  const drifted = [
    ...(stale(OUT_CSS, out) ? [OUT_CSS] : []),
    ...[...fonts].filter(([f, b]) => stale(join(FONT_DIR, `${f}-subset.woff2`), b)).map(([f]) => f),
  ];
  if (drifted.length) {
    console.error('Line Awesome subset is stale. Run `npm run generate:icons` and commit:');
    for (const d of drifted) console.error(`  ${d}`);
    process.exit(1);
  }
  console.log(`icons up to date (${sortedIcons.length} icons, weights: ${sortedWeights.join(', ')})`);
} else {
  mkdirSync(FONT_DIR, { recursive: true });
  writeFileSync(OUT_CSS, out, { encoding: 'utf8' });
  for (const [f, buf] of fonts) writeFileSync(join(FONT_DIR, `${f}-subset.woff2`), buf);
  const before = statSync(SRC_CSS).size;
  console.log(`css   ${before} B -> ${Buffer.byteLength(out)} B  (${sortedIcons.length}/${defined.size} icons)`);
  for (const [f, buf] of fonts) {
    const was = statSync(join(LA, 'fonts', `${f}.woff2`)).size;
    console.log(`font  ${f}: ${was} B -> ${buf.length} B`);
  }
}
