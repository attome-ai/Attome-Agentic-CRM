#!/usr/bin/env node
// Convert v1 vertical bundles into product-layer pack changesets.
//
//   node scripts/changesets/packs-from-verticals.mjs <verticals-dir> [--only a,b]
//
// Each <verticals-dir>/<name>/bundle.json becomes
// packs/<name>/changesets/0001-<name>.json: layer "product", scope <name>.
// Entity names the v1 bundles carry with the old module prefixes are mapped to
// the v2 names (no prefixes, V2-D483) before conversion. Deterministic: the id
// derives from the pack name and the timestamps are fixed, so re-running over
// unchanged input rewrites identical bytes.
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FORMAT, computeChecksum, toFileText, validateShape } from './lib.mjs';
import { bundleOps, changesetId, cmpStr } from './from-bundle.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const CONVERTED_AT = '2026-10-14T00:00:00Z';
const AUTHOR = 'packs (converted by scripts/changesets/packs-from-verticals.mjs)';

// v1 entity name -> v2 entity name.
const RENAMES = new Map([
  ['xrm_core_systemuser', 'user_account'],
  ['xrm_service_ticket', 'service_ticket'],
  ['xrm_service_offering', 'service_offering'],
  ['xrm_glossary_term', 'glossary_term'],
  ['xrm_webportal_user', 'webportal_user'],
  ['xrm_project', 'attome_project'],
]);

// The v1 bundles seeded their overview dashboards as rows of one flat
// `dashboard` entity (layout, canvas_columns, is_published). v2 dashboards are
// pages, sections and widgets (`attome_dashboard` and its children), so those
// rows have no v2 shape to land in and are left out; a pack's dashboards are
// rebuilt on the v2 model, not converted.
function renameRecordSetEntities(bundle) {
  bundle.record_sets = (bundle.record_sets ?? []).filter((set) => set.entity !== 'dashboard');
  // A single-entity stored query may not join: its row-level-security filter
  // scopes only its own table. A pack's joining report is rebuilt as a
  // multi-entity query on v2, not converted.
  bundle.queries = (bundle.queries ?? []).filter((q) => {
    const joins = q.entity && /\sJOIN\s/i.test(q.sql ?? '');
    if (joins) process.stderr.write(`  left out joining query: ${q.name}\n`);
    return !joins;
  });
  return bundle;
}

// v1 column names that v2 spells differently, inside stored-query SQL.
const COLUMN_RENAMES = [[/createdon/g, 'created_at']];

function rename(text) {
  let out = text;
  for (const [from, to] of COLUMN_RENAMES) out = out.replace(from, to);
  for (const [from, to] of RENAMES) out = out.split(`"${from}"`).join(`"${to}"`);
  // Privilege names ("entity.action").
  for (const [from, to] of RENAMES) out = out.split(`"${from}.`).join(`"${to}.`);
  // Unquoted table names inside stored-query SQL.
  for (const [from, to] of RENAMES) out = out.replace(new RegExp(`(?<![A-Za-z0-9_"])${from}(?![A-Za-z0-9_])`, 'g'), to);
  return out;
}

function platformFloor(requires) {
  return '>=0.1.0';
}

// A record set seeds rows by key, and the changeset engine matches and records
// them by the entity's business key. The platform entities a pack seeds
// (`glossary_term`, `service_offering`) declare theirs in the platform
// changesets, so the pack has nothing to declare.
function declareBusinessKeys(operations) {
  return operations.map((op, i) => ({ ...op, seq: i + 1 }));
}

export function convertPack(name, bundle) {
  // A pack's entity is created the way an admin creates one, so it gets the
  // Active/Inactive list-view pair its own views point at.
  const operations = declareBusinessKeys(bundleOps(bundle)).map((op) => {
    if (op.op !== 'create_entity') return op;
    const { list_views: _unused, ...args } = op.args;
    return { ...op, args };
  });
  if (operations.length === 0) return null;
  const modules = [...new Set((bundle.requires?.modules ?? []).filter((m) => /^[a-z][a-z0-9_]*$/.test(m)))].sort(cmpStr);
  const requires = { platform: platformFloor(bundle.requires) };
  if (modules.length) requires.modules = modules;
  const cs = {
    format: FORMAT,
    id: changesetId(`pack:${name}`),
    layer: 'product',
    scope: name,
    seq: 1,
    name,
    title: `Pack: ${name}`,
    description: `The ${name} pack's metadata, converted from its v1 vertical bundle.`,
    requires,
    author: AUTHOR,
    opened_at: CONVERTED_AT,
    closed_at: CONVERTED_AT,
    operations,
  };
  cs.checksum = computeChecksum(cs);
  const errs = validateShape(cs);
  if (errs.length) throw new Error(`${name}: converted changeset is invalid:\n  ${errs.join('\n  ')}`);
  return cs;
}

function main(argv) {
  const dir = argv.find((a) => !a.startsWith('--'));
  if (!dir) {
    process.stderr.write('usage: node scripts/changesets/packs-from-verticals.mjs <verticals-dir> [--only a,b]\n');
    return 2;
  }
  const i = argv.indexOf('--only');
  const only = i >= 0 ? new Set(argv[i + 1].split(',')) : null;
  let wrote = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (!entry.isDirectory() || (only && !only.has(entry.name))) continue;
    const file = join(dir, entry.name, 'bundle.json');
    if (!existsSync(file)) continue;

    const bundle = renameRecordSetEntities(JSON.parse(rename(readFileSync(file, 'utf8'))));
    const cs = convertPack(entry.name, bundle);
    if (!cs) {
      process.stderr.write(`${entry.name}: no components; skipped\n`);
      continue;
    }
    const outDir = join(ROOT, 'packs', entry.name, 'changesets');
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, `0001-${entry.name}.json`), toFileText(cs));
    process.stdout.write(`packs/${entry.name}/changesets/0001-${entry.name}.json (${cs.operations.length} operations)\n`);
    wrote += 1;
  }
  return wrote ? 0 : 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
