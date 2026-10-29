#!/usr/bin/env node
// S3-T1: the OpenAPI document the language SDKs are generated from.
//
// Reads the root openapi.json, keeps the operations `sdks/config.json`
// names (with every schema they reach), and writes
// `sdks/build/attome-sdk.json` as OpenAPI 3.0.3, the version every
// OpenAPI Generator language handles in full:
//
// - `type: ["x", "null"]` becomes `type: "x", nullable: true`; a `oneOf` or
//   `anyOf` with a `null` member loses it and becomes nullable;
// - `const` becomes a one-value `enum`; `examples` becomes `example`;
// - the generic record routes, whose bodies the server resolves from
//   runtime metadata (D-003) and so declares no schema for, get an object
//   body, and the record PATCH gets its required `If-Match` header (D-711),
//   as `config.json`'s `patches` say.
//
// Node only, no packages:  node sdks/subset.mjs [openapi.json] [out.json]

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const source = process.argv[2] ?? join(here, '..', 'openapi.json');
const target = process.argv[3] ?? join(here, 'build', 'attome-sdk.json');
const config = JSON.parse(readFileSync(join(here, 'config.json'), 'utf8'));
const doc = JSON.parse(readFileSync(source, 'utf8'));

const METHODS = ['get', 'put', 'post', 'delete', 'patch', 'head', 'options'];

/** The operations named in config, as {path, method, op}. */
const wanted = new Set(config.operations);
const kept = {};
const found = new Set();
for (const [path, item] of Object.entries(doc.paths)) {
  for (const method of METHODS) {
    const op = item[method];
    if (!op || !wanted.has(op.operationId)) continue;
    found.add(op.operationId);
    kept[path] ??= {};
    // The SDKs authenticate with an API key only.
    kept[path][method] = { ...structuredClone(op), security: [{ api_key: [] }] };
  }
}
const missing = [...wanted].filter(id => !found.has(id));
if (missing.length) {
  console.error(`subset: operations not in ${source}: ${missing.join(', ')}`);
  process.exit(1);
}

// Gaps the generic record routes leave in the document.
for (const patch of config.patches ?? []) {
  for (const item of Object.values(kept)) {
    for (const op of Object.values(item)) {
      if (op.operationId !== patch.operationId) continue;
      if (patch.requestBody && !op.requestBody) op.requestBody = patch.requestBody;
      for (const param of patch.parameters ?? []) {
        op.parameters ??= [];
        if (!op.parameters.some(p => p.name === param.name && p.in === param.in)) op.parameters.push(param);
      }
    }
  }
}

/** Every `#/components/schemas/X` reachable from `value`. */
function refsIn(value, out) {
  if (Array.isArray(value)) value.forEach(v => refsIn(v, out));
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (k === '$ref' && typeof v === 'string' && v.startsWith('#/components/schemas/')) {
        out.add(v.slice('#/components/schemas/'.length));
      } else refsIn(v, out);
    }
  }
  return out;
}

const schemas = {};
const queue = [...refsIn(kept, new Set())];
while (queue.length) {
  const name = queue.pop();
  if (schemas[name]) continue;
  const schema = doc.components.schemas[name];
  if (!schema) {
    console.error(`subset: schema ${name} is referenced but not defined`);
    process.exit(1);
  }
  schemas[name] = structuredClone(schema);
  for (const ref of refsIn(schema, new Set())) if (!schemas[ref]) queue.push(ref);
}

const THREE_ONE_ONLY = [
  'propertyNames', 'prefixItems', 'unevaluatedProperties', 'unevaluatedItems',
  'dependentRequired', 'dependentSchemas', 'contentEncoding', 'contentMediaType',
  'contentSchema', 'if', 'then', 'else', '$schema', '$id', '$anchor', '$comment',
];

const isNull = s => s && typeof s === 'object' && s.type === 'null' && Object.keys(s).length === 1;

/** 3.1 -> 3.0 for one schema object, in place, recursively. */
function down(node) {
  if (Array.isArray(node)) {
    node.forEach(down);
    return;
  }
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node.type)) {
    const types = node.type.filter(t => t !== 'null');
    if (types.length < node.type.length) node.nullable = true;
    if (types.length === 1) node.type = types[0];
    else if (types.length === 0) delete node.type;
    else {
      delete node.type;
      node.oneOf = types.map(t => ({ type: t }));
    }
  }
  for (const key of ['oneOf', 'anyOf']) {
    if (!Array.isArray(node[key])) continue;
    const rest = node[key].filter(s => !isNull(s));
    if (rest.length === node[key].length) continue;
    node.nullable = true;
    if (rest.length === 1) {
      delete node[key];
      if (rest[0].$ref) node.allOf = [rest[0]];
      else Object.assign(node, rest[0]);
    } else node[key] = rest;
  }
  if ('const' in node) {
    node.enum = [node.const];
    delete node.const;
  }
  // JSON Schema 2020-12 keywords OpenAPI 3.0 does not have; they only
  // narrow what is valid, so dropping them never refuses a real value.
  for (const key of THREE_ONE_ONLY) delete node[key];
  if (Array.isArray(node.examples)) {
    if (node.example === undefined && node.examples.length) node.example = node.examples[0];
    delete node.examples;
  }
  // An empty schema (`items: {}`) is any value in both versions.
  for (const value of Object.values(node)) down(value);
}

down(schemas);
down(kept);

const out = {
  openapi: '3.0.3',
  info: {
    title: 'Attome API (SDK subset)',
    description: `${config.description}\n\nGenerated by sdks/subset.mjs from openapi.json ${doc.info.version}.`,
    version: doc.info.version,
    // 3.0 licenses have a name and a url (3.1 adds `identifier`).
    license: doc.info.license && { name: doc.info.license.name, url: doc.info.license.url },
  },
  servers: [{ url: 'http://localhost:7865' }],
  security: [{ api_key: [] }],
  paths: kept,
  components: {
    schemas,
    securitySchemes: { api_key: doc.components.securitySchemes.api_key },
  },
};
mkdirSync(dirname(target), { recursive: true });
writeFileSync(target, `${JSON.stringify(out, null, 2)}\n`);
console.log(`subset: ${found.size} operations, ${Object.keys(schemas).length} schemas -> ${target}`);
