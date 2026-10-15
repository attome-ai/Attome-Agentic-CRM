#!/usr/bin/env node
// B12-T1: colours come from the theme tokens (`var(--color-…)`, set by
// `ThemeService` and `src/styles.css`), so light, dark and a customer's
// branding all apply everywhere. Counts, per stylesheet and per component's
// inline `styles`, the raw colours (`#hex`, `rgb()`, `rgba()`) outside a
// token: a token's own definition (`--name: #hex`) and a `var(--token,
// fallback)` fallback do not count. A file may not hold more than its count
// in `colours-baseline.json`, and a file not listed there may hold none, so
// the count only goes down.
//
//   node scripts/check-colours.mjs            check
//   node scripts/check-colours.mjs --update   write the current counts as the baseline
//   node scripts/check-colours.mjs --list     print every raw colour found

import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = join(dirname(fileURLToPath(import.meta.url)), '..');
const baselinePath = join(web, 'scripts', 'colours-baseline.json');
const roots = ['projects', 'src'].map(r => join(web, r));
const SKIP = new Set(['node_modules', 'dist', 'generated']);

/** Every stylesheet and component source under the web app, relative to `web/`. */
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

const RAW = /#[0-9a-fA-F]{3,8}\b|\brgba?\(\s*\d/g;
const FALLBACK = /var\(--[^,()]+,[^()]*(\([^()]*\))?[^()]*\)/g;

/** The CSS a file holds: the whole file, or a component's inline `styles`. */
function css(file, text) {
  if (!file.endsWith('.ts')) return text;
  return [...text.matchAll(/styles:\s*\[\s*`([\s\S]*?)`\s*\]/g)].map(m => m[1]).join('\n');
}

/** The raw colours in one file's CSS. */
export function rawColours(source) {
  const found = [];
  const text = source.replace(/\/\*[\s\S]*?\*\//g, ' ');
  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (trimmed.startsWith('--') || trimmed.startsWith('//')) continue;
    for (const match of line.replace(FALLBACK, 'var()').matchAll(RAW)) found.push(match[0]);
  }
  return found;
}

function main() {
  const counts = {};
  const listing = [];
  for (const file of roots.flatMap(root => sources(root)).sort()) {
    const found = rawColours(css(file, readFileSync(join(web, file), 'utf8')));
    if (found.length) {
      counts[file] = found.length;
      for (const colour of found) listing.push(`${file}: ${colour}`);
    }
  }
  const args = process.argv.slice(2);
  if (args.includes('--list')) {
    console.log(listing.join('\n'));
    return 0;
  }
  if (args.includes('--update')) {
    writeFileSync(baselinePath, JSON.stringify(counts, null, 2) + '\n');
    console.log(`check-colours: baseline written, ${Object.keys(counts).length} files`);
    return 0;
  }
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  const grown = Object.entries(counts).filter(([file, n]) => n > (baseline[file] ?? 0));
  if (grown.length) {
    console.error('check-colours: raw colours grew; use a theme token (var(--color-…)) instead:');
    for (const [file, n] of grown) {
      console.error(`  ${file}: ${n} raw colour(s), baseline ${baseline[file] ?? 0}`);
    }
    return 1;
  }
  const shrunk = Object.entries(baseline).filter(([file, n]) => (counts[file] ?? 0) < n);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  console.log(
    `check-colours: ok, ${total} raw colour(s) in ${Object.keys(counts).length} files` +
      (shrunk.length ? `; ${shrunk.length} file(s) now hold fewer, run with --update to lower the baseline` : ''),
  );
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main());
}
