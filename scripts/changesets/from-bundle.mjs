#!/usr/bin/env node
// Convert attome-bundle/v1 platform bundles into attome-changeset/v1 platform
// changesets (Solution 7 Phase 1.5, design §5.7, lane L6).
//
//   node scripts/changesets/from-bundle.mjs <bundle.json> [--seq N]   one bundle -> stdout
//   node scripts/changesets/from-bundle.mjs --all [--check]           every platform bundle ->
//                                                                     changesets/platform/
//
// One bundle becomes one changeset. Its operations follow the order the bundle
// engine applies the same bundle in (`bundle/apply.rs::build_steps`, over the
// bundle as `Bundle::normalize` sorts it): privileges -> entities -> fields
// (plain, then lookups, then formulas, across every entity) -> attribute patches
// -> queries -> views -> calendars -> sidebar (parents first) -> field-security
// profiles -> roles -> state models -> relationships -> apps -> rules
// -> record-set rows. Each component is its op's `definition`, with the child
// collections that have their own ops left out; a parent's child ops follow it
// directly, so the applier folds them into one reconcile of the parent.
//
// Two optional args the applier reads, beyond the catalogue's required ones:
// - `create_entity.args.list_views: false` — a platform bundle entity does not
//   get the Active/Inactive list-view pair the admin create route adds
//   (`provision::ensure_entity_list_views`); a recorded admin create does.
// - `upsert_record.args.key_fields` — the record set's key fields in declared
//   order: a record's derived id hashes its key in that order (`derived_id`
//   over `record_key`), and `target.key`'s member order does not survive a
//   JSON round trip.
//
// Deterministic: the changeset id is derived from the bundle name, the
// timestamps are fixed, and the file text is canonical, so re-running --all
// over unchanged bundles rewrites identical bytes (--check proves it).
//
// `--all` numbers the folder in platform BOOT order (BOOT_ORDER below, the
// order `crates/server/src/boot.rs` and `xrm-server/src/system.rs` apply the
// bundles in), so the implicit previous-number edge of every changeset is a
// real apply-order edge. A bundle with no components (xrm-report.json since
// D-479) yields no changeset.
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FORMAT, computeChecksum, toFileText, validateShape } from './lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
export const ROOT = resolve(HERE, '..', '..');
export const BUNDLE_DIR = join(ROOT, 'platform-bundles');
export const PLATFORM_DIR = join(ROOT, 'changesets', 'platform');

// The fixed timestamps of a converted changeset (conversion is not an
// authoring event; a fixed value keeps the output reproducible).
const CONVERTED_AT = '2026-09-29T00:00:00Z';
const AUTHOR = 'platform-bundles (converted by scripts/changesets/from-bundle.mjs)';

// `target.entity` of a multi-entity stored query (`QueryDef.entity == null`):
// `xrm_entity_engine::query_admin::MULTI_ENTITY_QUERY_TARGET`. Keep in step.
export const MULTI_ENTITY_QUERY_TARGET = 'multi_entity_stored_query_with_no_primary_entity_bound';

// Platform boot order: pre-build (crates/server/src/boot.rs), inside
// XrmSystem::build() (xrm-server/src/system.rs), post-build (boot.rs). A
// bundle applied twice at boot (xrm-audit, xrm-entity-autovalue) is listed at
// its first application.
export const BOOT_ORDER = [
  // boot.rs, before XrmSystem::build()
  'xrm-audit', 'xrm-entity-autovalue', 'xrm-workflow', 'xrm-docgen', 'xrm-integration',
  'xrm-ai-quality', 'xrm-ai-personality', 'xrm-ai-tone', 'xrm-ai-tone-data',
  'xrm-core-authentication-type', 'xrm-core-authentication-type-data', 'xrm-ai-provider',
  'xrm-ai-provider-data', 'xrm-ai-model-catalog', 'xrm-ai-model-catalog-data', 'xrm-ai-agent',
  'xrm-ai-capability-pack', 'xrm-ai-agent-data', 'xrm-core-apikey', 'xrm-search-saved-search',
  // system.rs, XrmSystem::build()
  'xrm-s2s', 'xrm-notification', 'xrm-security', 'xrm-webcrawl', 'xrm-document',
  'xrm-server-note', 'xrm-server-activity', 'xrm-server-communication',
  'xrm-server-communication-event', 'xrm-server-glossary', 'xrm-server-relationship',
  'xrm-server-follow', 'xrm-server-resource', 'xrm-server-tag', 'xrm-server-license',
  'xrm-reminder', 'xrm-compliance-consent', 'xrm-compliance-legal-matter', 'xrm-project',
  'xrm-service', 'xrm-portal', 'xrm-grc', 'xrm-metric', 'xrm-dashboard',
  'xrm-server-profiler-finding',
  // boot.rs, after XrmSystem::build()
  'xrm-report-reports', 'xrm-ai-bot-analytics', 'xrm-ai-bot-analytics-data', 'trd-governance',
  // not applied at boot (D-479 emptied it); converts to nothing
  'xrm-report',
];

// ---------------------------------------------------------------------------
// Ordering helpers: Rust's `str` Ord is byte order; compare UTF-8 bytes.
// ---------------------------------------------------------------------------
const bytes = (s) => Buffer.from(String(s), 'utf8');
export function cmpStr(a, b) { return Buffer.compare(bytes(a), bytes(b)); }
function cmpTuple(a, b) {
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i]; const y = b[i];
    if (x === y) continue;
    if (x === undefined || x === null) return -1; // Option::None < Some
    if (y === undefined || y === null) return 1;
    const c = typeof x === 'number' && typeof y === 'number' ? (x < y ? -1 : 1) : cmpStr(x, y);
    if (c !== 0) return c;
  }
  return 0;
}
const by = (key) => (a, b) => cmpTuple(key(a), key(b));
const sorted = (list, key) => [...(list ?? [])].sort(by(key));
function cmpPath(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const c = cmpStr(a[i], b[i]);
    if (c !== 0) return c;
  }
  return a.length - b.length;
}
// serde_json's compact `Value::to_string` for the scalar values keys carry.
const valueText = (v) => (v === undefined ? '' : JSON.stringify(v));

function omit(obj, keys) {
  const out = { ...obj };
  for (const k of keys) delete out[k];
  return out;
}

// A deterministic UUIDv7-shaped id (version 7, RFC 4122 variant) for a
// converted changeset: sha256 over a fixed namespace and the bundle name.
export function changesetId(name) {
  const h = createHash('sha256').update(`attome-platform-changeset:${name}`, 'utf8').digest();
  const b = Buffer.from(h.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x70;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = b.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function platformFloor(requires) {
  const v = String(requires?.platform_version ?? '').trim();
  const m = /^(?:>=)?\s*(\d+\.\d+\.\d+)$/.exec(v);
  return `>=${m ? m[1] : '0.0.0'}`;
}

// ---------------------------------------------------------------------------
// Bundle -> operations
// ---------------------------------------------------------------------------
export function bundleOps(bundle) {
  const ops = [];
  const push = (op, phase, target, args) => ops.push(args === undefined ? { op, phase, target } : { op, phase, target, args });
  const E = 'expand';

  for (const p of sorted(bundle.privileges, (p) => [p.key])) {
    push('ensure_privilege', E, { privilege: p.key }, { definition: p });
  }

  const entities = sorted(bundle.entities, (e) => [e.logicalname]);
  for (const e of entities) {
    push('create_entity', E, { entity: e.logicalname }, { definition: omit(e, ['attributes']), list_views: false });
  }
  const kind = (a) => (a.field_type === 'lookup' ? 'lookup' : a.field_type === 'formula' ? 'formula' : 'plain');
  for (const pass of ['plain', 'lookup', 'formula']) {
    for (const e of entities) {
      for (const a of sorted(e.attributes, (a) => [a.logicalname]).filter((a) => kind(a) === pass)) {
        push('add_field', E, { entity: e.logicalname, field: a.logicalname }, { definition: a });
      }
    }
  }
  for (const p of sorted(bundle.attribute_patches, (p) => [p.entity, p.attribute.logicalname])) {
    push('add_field', E, { entity: p.entity, field: p.attribute.logicalname }, { definition: p.attribute });
  }

  for (const q of sorted(bundle.queries, (q) => [q.entity ?? null, q.name])) {
    const def = { ...q, entity_mappings: sorted(q.entity_mappings, (m) => [m.entity, m.id_column]) };
    push('upsert_query', E, { entity: q.entity ?? MULTI_ENTITY_QUERY_TARGET, query: q.name }, { definition: def });
  }
  for (const v of sorted(bundle.views, (v) => [v.entity, v.name])) {
    push('upsert_view', E, { entity: v.entity, view: v.name }, { definition: v });
  }

  for (const c of sorted(bundle.calendars, (c) => [c.name])) {
    push('upsert_calendar', E, { calendar: c.name }, { definition: omit(c, ['holidays', 'exceptions']) });
    for (const h of sorted(c.holidays, (h) => [h.holiday_date, h.name])) {
      push('add_calendar_holiday', E, { calendar: c.name, date: h.holiday_date }, { definition: h });
    }
    for (const x of sorted(c.exceptions, (x) => [x.exception_date])) {
      push('add_calendar_exception', E, { calendar: c.name, exception: x.exception_date }, { definition: x });
    }
  }

  // Parents before children: sorted by path, then (stably) by depth.
  const sidebar = [...(bundle.sidebar ?? [])].sort((a, b) => cmpPath(a.path, b.path));
  sidebar.sort((a, b) => a.path.length - b.path.length);
  for (const s of sidebar) {
    const def = { ...s, privileges: [...new Set(s.privileges ?? [])].sort(cmpStr) };
    push('upsert_sidebar_item', E, { path: s.path.join('/') }, { definition: def });
  }

  for (const p of sorted(bundle.field_security_profiles, (p) => [p.name])) {
    push('upsert_field_profile', E, { profile: p.name }, { definition: omit(p, ['fields']) });
    for (const f of sorted(p.fields, (f) => [f.entity, f.field])) {
      push('set_field_profile_field', E, { profile: p.name, entity: f.entity, field: f.field }, {
        permissions: { can_read: f.can_read, can_update: f.can_update },
      });
    }
  }

  for (const r of sorted(bundle.roles, (r) => [r.name])) {
    push('upsert_role', E, { role: r.name }, {
      definition: omit(r, ['privileges', 'entity_access', 'field_security_profiles']),
    });
    for (const g of sorted(r.privileges, (g) => [g.privilege])) {
      push('grant_role_privilege', E, { role: r.name, privilege: g.privilege }, { depth: null });
      const conditions = [...(g.conditions ?? [])].sort(by((c) => [c.field, c.operator, valueText(c.value)]));
      for (const c of conditions) {
        push('add_role_grant_condition', E, {
          role: r.name, privilege: g.privilege, condition: `${c.field}|${c.operator}|${valueText(c.value)}`,
        }, { definition: c });
      }
    }
    for (const a of sorted(r.entity_access, (a) => [a.entity])) {
      push('set_role_entity_access', E, { role: r.name, entity: a.entity }, { access: omit(a, ['entity']) });
    }
    for (const profile of [...new Set(r.field_security_profiles ?? [])].sort(cmpStr)) {
      push('assign_field_profile', E, { profile, role: r.name });
    }
  }

  for (const m of sorted(bundle.state_models, (m) => [m.entity_logicalname])) {
    push('upsert_state_model', E, { entity: m.entity_logicalname }, { definition: omit(m, ['transitions']) });
    for (const t of sorted(m.transitions, (t) => [t.from_state, t.to_state])) {
      push('upsert_state_transition', E, {
        entity: m.entity_logicalname, transition: `${t.from_state}->${t.to_state}`,
      }, { definition: t });
    }
  }

  for (const r of sorted(bundle.relationships, (r) => [r.name])) {
    push('upsert_relationship', E, { relationship: r.name }, { definition: r });
  }
  for (const a of sorted(bundle.apps, (a) => [a.name])) {
    push('upsert_app', E, { app: a.name }, { definition: a });
  }
  for (const r of sorted(bundle.rules, (r) => [`${r.entity_logicalname}:${r.name}`])) {
    push('upsert_rule', E, { entity: r.entity_logicalname, rule: r.name }, { definition: r });
  }

  for (const rs of sorted(bundle.record_sets, (rs) => [rs.entity])) {
    const keys = rs.key_fields ?? [];
    const rows = [...(rs.rows ?? [])].sort(by((row) => keys.map((k) => valueText(row[k]))));
    for (const row of rows) {
      const key = {};
      for (const k of keys) key[k] = row[k];
      push('upsert_record', E, { entity: rs.entity, key }, { values: row, key_fields: keys });
    }
  }

  return ops.map((o, i) => ({ seq: i + 1, ...o }));
}

// One bundle document -> one changeset (null when the bundle has no content).
export function fromBundle(name, bundle, seq) {
  const operations = bundleOps(bundle);
  if (operations.length === 0) return null;
  const modules = [...new Set((bundle.requires?.modules ?? []).filter((m) => /^[a-z][a-z0-9_]*$/.test(m)))].sort(cmpStr);
  const requires = { platform: platformFloor(bundle.requires) };
  if (modules.length) requires.modules = modules;
  const cs = {
    format: FORMAT,
    id: changesetId(name),
    layer: 'platform',
    scope: 'platform',
    seq,
    name,
    title: `Platform definitions: ${name}`,
    description: `Converted from platform-bundles/${name}.json (Solution 7 Phase 1.5, D-785).`,
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

export function readBundle(name, dir = BUNDLE_DIR) {
  return JSON.parse(readFileSync(join(dir, `${name}.json`), 'utf8'));
}

// Every platform bundle, in boot order, as `{ file, cs }` (empty bundles skipped).
export function convertAll(dir = BUNDLE_DIR) {
  const onDisk = readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => f.slice(0, -5)).sort();
  const missing = onDisk.filter((n) => !BOOT_ORDER.includes(n));
  if (missing.length) throw new Error(`platform bundles not in BOOT_ORDER: ${missing.join(', ')}`);
  const gone = BOOT_ORDER.filter((n) => !onDisk.includes(n));
  if (gone.length) throw new Error(`BOOT_ORDER names bundles that do not exist: ${gone.join(', ')}`);
  const out = [];
  for (const name of BOOT_ORDER) {
    const cs = fromBundle(name, readBundle(name, dir), out.length + 1);
    if (cs) out.push({ file: `${String(cs.seq).padStart(4, '0')}-${cs.name}.json`, cs });
  }
  return out;
}

// Writes (or, with check, compares) the whole platform folder. Returns the
// list of differences in check mode (empty = up to date).
export function writeAll({ check = false, dir = PLATFORM_DIR } = {}) {
  const converted = convertAll();
  const want = new Map(converted.map(({ file, cs }) => [file, toFileText(cs)]));
  const have = existsSync(dir) ? readdirSync(dir).filter((f) => f.endsWith('.json')) : [];
  const diffs = [];
  for (const [file, text] of want) {
    const path = join(dir, file);
    if (!existsSync(path) || readFileSync(path, 'utf8') !== text) diffs.push(`${file}: missing or stale`);
  }
  for (const f of have) if (!want.has(f)) diffs.push(`${f}: no longer produced`);
  if (!check) {
    mkdirSync(dir, { recursive: true });
    for (const f of have) if (!want.has(f)) rmSync(join(dir, f));
    for (const [file, text] of want) writeFileSync(join(dir, file), text);
  }
  return diffs;
}

function main(argv) {
  if (argv.includes('--all')) {
    const check = argv.includes('--check');
    const diffs = writeAll({ check });
    if (check && diffs.length) {
      for (const d of diffs) process.stderr.write(`stale: ${d}\n`);
      process.stderr.write('run: node scripts/changesets/from-bundle.mjs --all\n');
      return 1;
    }
    process.stdout.write(check ? 'changesets/platform is up to date\n' : `wrote ${PLATFORM_DIR}\n`);
    return 0;
  }
  const file = argv.find((a) => !a.startsWith('--'));
  if (!file) {
    process.stderr.write('usage: node scripts/changesets/from-bundle.mjs <bundle.json> [--seq N] | --all [--check]\n');
    return 2;
  }
  const i = argv.indexOf('--seq');
  const seq = i >= 0 ? Number(argv[i + 1]) : 1;
  const name = basename(file).replace(/\.json$/, '');
  const cs = fromBundle(name, JSON.parse(readFileSync(file, 'utf8')), seq);
  if (!cs) {
    process.stderr.write(`${name}: the bundle has no components; nothing to convert\n`);
    return 1;
  }
  process.stdout.write(toFileText(cs));
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
