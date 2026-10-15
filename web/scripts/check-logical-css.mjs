#!/usr/bin/env node
// B21-T1: layouts mirror for Arabic because they use logical properties
// (`margin-inline-start`, `inset-inline-end`, `text-align: start`), never the
// physical left and right. Counts, per stylesheet and per component's inline
// `styles`, the physical declarations (`margin-left`, `padding-right`,
// `border-left`, `left:`, `right:`, `text-align: left|right`,
// `float: left|right`) in rules that are not themselves direction-specific
// (a selector naming `rtl`, `ltr` or `[dir]` may set physical sides on
// purpose), leaving out `left: 50%` centring. A file may not hold more than
// its count in `logical-css-baseline.json`, and a file not listed there may
// hold none, so the count only goes down.
//
//   node scripts/check-logical-css.mjs            check
//   node scripts/check-logical-css.mjs --update   write the current counts as the baseline
//   node scripts/check-logical-css.mjs --list     print every physical declaration found

import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = join(dirname(fileURLToPath(import.meta.url)), '..');
const baselinePath = join(web, 'scripts', 'logical-css-baseline.json');
const roots = ['projects', 'src'].map(r => join(web, r));
const SKIP = new Set(['node_modules', 'dist', 'generated']);

function sources(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name) || name.startsWith('.')) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (/\.(css|scss)$/.test(name) || (name.endsWith('.ts') && !name.endsWith('.spec.ts'))) {
      out.push(relative(web, path).split(sep).join('/'));
    }
  }
  return out;
}

function css(file, text) {
  if (!file.endsWith('.ts')) return text;
  return [...text.matchAll(/styles:\s*\[\s*`([\s\S]*?)`\s*\]/g)].map(m => m[1]).join('\n');
}

const DIRECTIONAL = /rtl|ltr|\[dir|:dir\(/;
const PHYSICAL = [
  /(?<![-\w])(?:margin|padding)-(?:left|right)\s*:/g,
  /(?<![-\w])border-(?:left|right)(?:-[a-z]+)?\s*:/g,
  /(?<![-\w])(?:left|right)\s*:(?![^;}]*50%)/g,
  /text-align\s*:\s*(?:left|right)\b/g,
  /float\s*:\s*(?:left|right)\b/g,
];

/** The physical declarations in one file's CSS. */
export function physicalDeclarations(source) {
  const found = [];
  const text = source.replace(/\/\*[\s\S]*?\*\//g, ' ');
  for (const match of text.matchAll(/([^{}]*)\{([^{}]*)\}/g)) {
    const [, selector, body] = match;
    if (DIRECTIONAL.test(selector) || selector.trim().startsWith('@')) continue;
    for (const pattern of PHYSICAL) {
      for (const hit of body.matchAll(pattern)) found.push(hit[0].replace(/\s+/g, ''));
    }
  }
  return found;
}

function main() {
  const counts = {};
  const listing = [];
  for (const file of roots.flatMap(root => sources(root)).sort()) {
    let text;
    try {
      text = readFileSync(join(web, file), 'utf8');
    } catch {
      continue;
    }
    const found = physicalDeclarations(css(file, text));
    if (found.length) {
      counts[file] = found.length;
      for (const item of found) listing.push(`${file}: ${item}`);
    }
  }
  const args = process.argv.slice(2);
  if (args.includes('--list')) {
    console.log(listing.join('\n'));
    return 0;
  }
  if (args.includes('--update')) {
    writeFileSync(baselinePath, JSON.stringify(counts, null, 2) + '\n');
    console.log(`check-logical-css: baseline written, ${Object.keys(counts).length} files`);
    return 0;
  }
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  const grown = Object.entries(counts).filter(([file, n]) => n > (baseline[file] ?? 0));
  if (grown.length) {
    console.error('check-logical-css: physical left/right grew; use logical properties so Arabic mirrors:');
    for (const [file, n] of grown) {
      console.error(`  ${file}: ${n}, baseline ${baseline[file] ?? 0}`);
      for (const line of listing.filter(l => l.startsWith(`${file}: `))) console.error(`    ${line.slice(file.length + 2)}`);
    }
    return 1;
  }
  const shrunk = Object.entries(baseline).filter(([file, n]) => (counts[file] ?? 0) < n);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  console.log(
    `check-logical-css: ok, ${total} physical declaration(s) in ${Object.keys(counts).length} files` +
      (shrunk.length ? `; ${shrunk.length} file(s) now hold fewer, run with --update to lower the baseline` : ''),
  );
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main());
}
