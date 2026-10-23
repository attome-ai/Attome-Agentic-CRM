import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { NODE_CONFIG_SCHEMA } from './services/workflow-admin.service';

// Lockstep guard, same shape as admin/field-types.lockstep.spec.ts: the
// inspector's generated config form is driven by NODE_CONFIG_SCHEMA, a
// hand-maintained mirror of the config keys each executor in
// `attome_workflow::scheduler` (plus `trigger_index::rebuild_entry_rows`)
// actually reads. Drift is silent and nasty in exactly one direction — an
// executor gains a key, the schema does not, and the form quietly offers no
// way to set it — so this test reads the Rust sources and fails when a
// `config.get("…")` has no matching schema field.
//
// The reverse direction is asserted too (no schema field for a key nothing
// reads), which catches a typo'd key name that would silently never apply.

/** Rust fn name (or module-level marker) → node `type` string it configures. */
const EXECUTOR_TO_NODE_TYPE: Record<string, string[]> = {
  eval_condition:            ['condition'],
  execute_entity_write:      ['create_record', 'update_record'],
  execute_restore_record:    ['restore_record'],
  execute_duplicate_check:   ['duplicate_check'],
  execute_assign:            ['assign'],
  execute_send_notification: ['send_notification'],
  execute_approval:          ['approval'],
  execute_wait:              ['wait'],
  execute_wait_for_event:    ['wait_for_event'],
  wait_until:                ['wait', 'wait_for_event'],
  wait_base:                 ['wait', 'wait_for_event'],
  execute_sub_workflow:      ['sub_workflow'],
  execute_for_each:          ['for_each'],
  for_each_batch_size:       ['for_each'],
  execute_webhook:           ['webhook'],
  execute_module_step:       ['module_step'],
  module_step_handler:       ['module_step'],
  // A blocked step's retry wait (`retry_after_seconds`) is read when its
  // outcome is mapped.
  step_node_outcome:         ['module_step'],
  join_mode_and_threshold:   ['join'],
  rebuild_entry_rows:        ['trigger'],
  entry_condition:           ['trigger'],
};

function rustSource(relPath: string): string {
  // process.cwd() is the angular/ workspace root under the unit-test builder.
  return readFileSync(resolve(process.cwd(), relPath), 'utf-8');
}

/**
 * Splits a Rust file into `fnName -> body` at top-level `fn`/`async fn`
 * boundaries. Coarse, but these executors are all free functions in one flat
 * module, and over-capturing a trailing helper would only ever *add* keys —
 * which surfaces as a loud failure, not a silent pass.
 */
function functionBodies(src: string): Record<string, string> {
  // `pub(crate)` (not just bare `pub`) shows up here now that a couple of
  // these executors (`eval_condition`, most visibly) are also called from
  // `simulate.rs`'s dry-run pass, a different module in the same crate.
  const starts = [...src.matchAll(/^(?:pub(?:\(crate\))? )?(?:async )?fn (\w+)/gm)];
  const out: Record<string, string> = {};
  starts.forEach((m, i) => {
    const from = m.index ?? 0;
    const to = i + 1 < starts.length ? starts[i + 1].index ?? src.length : src.length;
    out[m[1]] = src.slice(from, to);
  });
  return out;
}

/**
 * Every `config.get("key")` in a body. `\s*` spans newlines so the rustfmt'd
 * `node\n    .config\n    .get("template_key")` chains match as well as the
 * single-line `config.get("op")` in `eval_condition`.
 */
function configKeys(body: string): string[] {
  return [...body.matchAll(/config\s*\.\s*get\("(\w+)"\)/g)].map(m => m[1]);
}

function backendKeysByNodeType(): Record<string, Set<string>> {
  const bodies = {
    ...functionBodies(rustSource('../crates/engine/attome-workflow/src/scheduler.rs')),
    ...functionBodies(rustSource('../crates/engine/attome-workflow/src/trigger_index.rs')),
  };

  const byType: Record<string, Set<string>> = {};
  for (const [fnName, nodeTypes] of Object.entries(EXECUTOR_TO_NODE_TYPE)) {
    const body = bodies[fnName];
    if (!body) throw new Error(`could not find "fn ${fnName}" in the attome-workflow sources`);
    const keys = configKeys(body);
    if (keys.length === 0) throw new Error(`fn ${fnName} read no config keys — regex drift?`);
    for (const t of nodeTypes) {
      byType[t] ??= new Set();
      for (const k of keys) byType[t].add(k);
    }
  }
  return byType;
}

describe('NODE_CONFIG_SCHEMA lockstep with the attome-workflow executors', () => {
  const backend = backendKeysByNodeType();

  it('covers every node type that reads config', () => {
    expect(Object.keys(backend).sort()).toEqual(Object.keys(NODE_CONFIG_SCHEMA).sort());
  });

  for (const [nodeType, keys] of Object.entries(backend)) {
    it(`${nodeType}: schema fields match the keys the executor reads`, () => {
      const schemaKeys = (NODE_CONFIG_SCHEMA[nodeType] ?? []).map(f => f.key).sort();
      expect(schemaKeys).toEqual([...keys].sort());
    });
  }

  it('gives every field a label, and every select a default among its options', () => {
    for (const [nodeType, fields] of Object.entries(NODE_CONFIG_SCHEMA)) {
      for (const f of fields) {
        expect(f.label, `${nodeType}.${f.key} label`).toBeTruthy();
        if (f.kind !== 'select') continue;
        const values = (f.options ?? []).map(o => o.value);
        expect(values.length, `${nodeType}.${f.key} options`).toBeGreaterThan(0);
        expect(values, `${nodeType}.${f.key} default`).toContain(String(f.default));
      }
    }
  });

  it('gates every showIf on a real sibling field with reachable values', () => {
    for (const [nodeType, fields] of Object.entries(NODE_CONFIG_SCHEMA)) {
      for (const f of fields) {
        if (!f.showIf) continue;
        const gate = fields.find(g => g.key === f.showIf!.key);
        expect(gate, `${nodeType}.${f.key} showIf target`).toBeDefined();
        const allowed = (gate?.options ?? []).map(o => o.value);
        for (const v of f.showIf.in) {
          expect(allowed, `${nodeType}.${f.key} showIf value ${v}`).toContain(v);
        }
      }
    }
  });
});
