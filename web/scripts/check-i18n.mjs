#!/usr/bin/env node
// B20-T2: no new hard-coded interface text. Counts, per template, the text a
// person would read that does not come from the catalogue (`| translate`):
// text between tags, and the literal `placeholder`, `title`, `aria-label` and
// `alt` attributes. A template may not hold more than its count in
// `i18n-literals-baseline.json`, and a template not listed there may hold
// none, so the count only goes down. Missing catalogue keys are the other
// half of the gate, checked by `catalog-coverage.spec.ts` in `test:base`.
//
//   node scripts/check-i18n.mjs            check
//   node scripts/check-i18n.mjs --update   write the current counts as the baseline
//   node scripts/check-i18n.mjs --list     print every literal found

import { readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = join(dirname(fileURLToPath(import.meta.url)), '..');
const baselinePath = join(web, 'scripts', 'i18n-literals-baseline.json');
const roots = ['projects', 'src'].map(r => join(web, r));

/** Every `.html` template under the web app, as paths relative to `web/`. */
function templates(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name.startsWith('.')) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) templates(path, out);
    else if (name.endsWith('.html')) out.push(relative(web, path).split(sep).join('/'));
  }
  return out;
}

const LETTERS = /[A-Za-z؀-ۿ]{2,}/;
const BLOCK = /@(?:if|else if|else|for|switch|case|default|defer|empty|placeholder|loading|error)\b[^{}]*\{/g;

/** The literal, readable text in one template. */
export function literals(html) {
  const found = [];
  const text = html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(code|pre|kbd|style|script|svg)\b[\s\S]*?<\/\1>/gi, ' ');
  for (const match of text.matchAll(/>([^<>]+)</g)) {
    const chunk = match[1]
      .replace(/\{\{[\s\S]*?\}\}/g, ' ')
      .replace(/@let\s[^;]*;/g, ' ')
      .replace(BLOCK, ' ')
      .replace(/[{}]/g, ' ')
      .replace(/&[a-z]+;|&#\d+;/gi, ' ')
      .trim();
    if (LETTERS.test(chunk)) found.push(chunk.replace(/\s+/g, ' '));
  }
  for (const match of text.matchAll(/\s(placeholder|title|aria-label|alt)="([^"]*)"/g)) {
    const value = match[2];
    if (!value.includes('{{') && LETTERS.test(value)) found.push(`${match[1]}="${value}"`);
  }
  return found;
}

function main() {
  const counts = {};
  const listing = [];
  for (const file of roots.flatMap(root => templates(root)).sort()) {
    const found = literals(readFileSync(join(web, file), 'utf8'));
    if (found.length) {
      counts[file] = found.length;
      for (const text of found) listing.push(`${file}: ${text}`);
    }
  }
  const args = process.argv.slice(2);
  if (args.includes('--list')) {
    console.log(listing.join('\n'));
    return 0;
  }
  if (args.includes('--update')) {
    writeFileSync(baselinePath, JSON.stringify(counts, null, 2) + '\n');
    console.log(`check-i18n: baseline written, ${Object.keys(counts).length} templates`);
    return 0;
  }
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  const grown = Object.entries(counts).filter(([file, n]) => n > (baseline[file] ?? 0));
  if (grown.length) {
    console.error('check-i18n: hard-coded interface text grew; use the catalogue (| translate) instead:');
    for (const [file, n] of grown) {
      console.error(`  ${file}: ${n} literal(s), baseline ${baseline[file] ?? 0}`);
      for (const line of listing.filter(l => l.startsWith(`${file}: `))) console.error(`    ${line.slice(file.length + 2)}`);
    }
    return 1;
  }
  const shrunk = Object.entries(baseline).filter(([file, n]) => (counts[file] ?? 0) < n);
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  console.log(
    `check-i18n: ok, ${total} literal(s) in ${Object.keys(counts).length} templates` +
      (shrunk.length ? `; ${shrunk.length} template(s) now hold fewer, run with --update to lower the baseline` : ''),
  );
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  process.exit(main());
}
