// AK5-T1: the exit archive loader. Run with `node --test scripts/exit/load-postgres.test.mjs`.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import { buildSql, columnType, headerColumns, ident, readArchive } from './load-postgres.mjs';

const entities = [
  {
    logicalname: 'account',
    display_name: "Customer's account",
    attributes: [
      { logicalname: 'name', display_name: 'Name', field_type: 'text' },
      { logicalname: 'revenue', field_type: 'currency' },
      { logicalname: 'tags', field_type: 'choice', options: { multi: true } },
      { logicalname: 'parent_ref', field_type: 'lookup', lookup_entity: 'account' },
    ],
  },
];

test('field types map to PostgreSQL types', () => {
  assert.equal(columnType({ field_type: 'date_time' }), 'timestamptz');
  assert.equal(columnType({ field_type: 'choice', options: { multi: true } }), 'text[]');
  assert.equal(columnType({ field_type: 'lookup' }), 'uuid');
  assert.equal(columnType({ field_type: 'something_new' }), 'text');
  assert.equal(columnType(undefined), 'text');
});

test('identifiers and headers are quoted and read safely', () => {
  assert.equal(ident('a"b'), '"a""b"');
  assert.deepEqual(headerColumns('id,"name",revenue\r\n'), ['id', 'name', 'revenue']);
});

test('typed tables, comments, copy commands and optional foreign keys', () => {
  const tables = new Map([
    ['account', { file: 'data/account.csv', columns: ['id', 'is_active', 'name', 'revenue', 'tags', 'parent_ref', 'gone'] }],
    ['audit_header', { file: 'audit/audit_header.csv', columns: ['id', 'operation'] }],
  ]);
  const { schema, load } = buildSql(entities, tables, { foreignKeys: true });
  assert.match(schema, /CREATE SCHEMA IF NOT EXISTS "attome_exit";/);
  assert.match(schema, /"id" uuid,\n  "is_active" boolean,\n  "name" text,\n  "revenue" numeric,\n  "tags" text\[\],\n  "parent_ref" uuid,\n  "gone" text,\n  PRIMARY KEY \("id"\)/);
  assert.match(schema, /COMMENT ON TABLE "account" IS 'Customer''s account';/);
  // The audit table is not an entity: every column is text, no key.
  assert.match(schema, /CREATE TABLE IF NOT EXISTS "audit_header" \(\n  "id" text,\n  "operation" text\n\);/);
  assert.match(schema, /ALTER TABLE "account" ADD FOREIGN KEY \("parent_ref"\) REFERENCES "account" \("id"\) NOT VALID;/);
  assert.match(load, /\\copy "account" \("id", "is_active", "name", "revenue", "tags", "parent_ref", "gone"\) FROM 'data\/account.csv' WITH \(FORMAT csv, HEADER true\)/);
  assert.doesNotMatch(buildSql(entities, tables).schema, /FOREIGN KEY/);
});

test('an extracted archive folder is read', () => {
  const dir = mkdtempSync(join(tmpdir(), 'attome-exit-'));
  try {
    mkdirSync(join(dir, 'metadata'));
    mkdirSync(join(dir, 'data'));
    writeFileSync(join(dir, 'metadata', 'bundle.json'), JSON.stringify({ format: 'attome-bundle/v1', entities }));
    writeFileSync(join(dir, 'data', 'account.csv'), '﻿id,name\n0190a8b4-0000-7000-8000-000000000001,Acme\n');
    const { entities: read, tables } = readArchive(dir);
    assert.equal(read.length, 1);
    assert.deepEqual(tables.get('account'), { file: 'data/account.csv', columns: ['id', 'name'] });
    assert.throws(() => readArchive(join(dir, 'missing')), /not found/);
    assert.ok(readFileSync(join(dir, 'data', 'account.csv'), 'utf8').includes('Acme'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
