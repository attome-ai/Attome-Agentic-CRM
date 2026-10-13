import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { XRM_FIELD_TYPES } from './admin.service';

// Lockstep guard (P-frontend-baseline): XRM_FIELD_TYPES here and the FieldType enum
// in attome-core/src/field_type.rs are two hand-maintained lists that MUST agree
// (db-and-migrations skill: "adding a FieldType touches ALL of ... the Angular
// XRM_FIELD_TYPES constant ... miss one and you get silent drift"). This test reads
// the Rust source directly so a variant added/removed/renamed on one side without the
// other fails here instead of at runtime against a live backend.

function pascalToSnake(s: string): string {
  return s.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

function backendFieldTypes(): string[] {
  // process.cwd() is the angular/ workspace root (where angular.json lives) when
  // the unit-test builder runs — resolve up to the repo root, then into the crate.
  // D-103: crates/ nests each crate under crates/engine/ (was crates/attome-core
  // directly under crates/) — path below updated to match.
  const rustFile = resolve(process.cwd(), '../crates/engine/attome-core/src/field_type.rs');
  const src = readFileSync(rustFile, 'utf-8');

  const enumMatch = src.match(/pub enum FieldType\s*\{([^}]*)\}/);
  if (!enumMatch) throw new Error(`could not find "pub enum FieldType { ... }" in ${rustFile}`);

  return enumMatch[1]
    .split(',')
    .map((line: string) => line.trim())
    .filter((line: string) => line.length > 0)
    .map(pascalToSnake);
}

describe('XRM_FIELD_TYPES lockstep with attome-core::FieldType', () => {
  it('matches the backend FieldType enum exactly (same members, same set)', () => {
    const backend = backendFieldTypes().sort();
    const frontend = [...XRM_FIELD_TYPES].sort();
    expect(frontend).toEqual(backend);
  });
});
