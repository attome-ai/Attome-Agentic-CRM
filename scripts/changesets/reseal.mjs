#!/usr/bin/env node
// Recompute the `checksum` of changeset documents (RFC 8785 canonical JSON,
// sha256 over the document without its `checksum` member), the same value
// `attome_api::changeset::jcs::document_checksum` computes.
//
//   node scripts/changesets/reseal.mjs [--check] <file-or-dir>...
//
// Without --check it rewrites a stale `"checksum"` line in place (the rest of
// the file is left byte for byte as it was). With --check it only reports and
// exits 1 when any file is stale. Only for documents not yet released: a
// closed changeset is immutable.

import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

function canonicalize(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return `[${v.map(canonicalize).join(",")}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(v[k])}`).join(",")}}`;
}

export function checksumOf(doc) {
  const { checksum: _drop, ...rest } = doc;
  return `sha256:${createHash("sha256").update(canonicalize(rest), "utf8").digest("hex")}`;
}

function* files(path) {
  if (statSync(path).isDirectory()) {
    for (const name of readdirSync(path).sort()) yield* files(join(path, name));
  } else if (path.endsWith(".json")) {
    yield path;
  }
}

const args = process.argv.slice(2);
const check = args.includes("--check");
const targets = args.filter((a) => a !== "--check");
if (targets.length === 0) {
  console.error("usage: reseal.mjs [--check] <file-or-dir>...");
  process.exit(2);
}

let stale = 0;
let total = 0;
for (const target of targets) {
  for (const file of files(target)) {
    const text = readFileSync(file, "utf8");
    const doc = JSON.parse(text);
    if (typeof doc !== "object" || doc === null || typeof doc.checksum !== "string") continue;
    total += 1;
    const want = checksumOf(doc);
    if (want === doc.checksum) continue;
    stale += 1;
    console.log(`${check ? "stale" : "resealed"}: ${file}`);
    if (!check) {
      writeFileSync(file, text.replace(doc.checksum, want), "utf8");
    }
  }
}
console.log(`${total} document(s), ${stale} ${check ? "stale" : "resealed"}`);
process.exit(check && stale > 0 ? 1 : 0);
