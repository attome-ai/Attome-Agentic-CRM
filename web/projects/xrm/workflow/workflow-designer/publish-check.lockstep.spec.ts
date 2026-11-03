import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

// Lockstep guard, same shape as node-config-schema.lockstep.spec.ts:
// `publishProblems` mirrors `attome_workflow::graph::validate` so a problem
// shows while the builder edits. A new check in the engine would be missed
// silently here (it would only surface at publish), so this reads the Rust and
// fails when the count of refusals changes: add the check to `publish-check.ts`
// with its i18n key, then update the count.

/** The refusals in `validate`, two of which the designer cannot mirror (see below). */
const VALIDATE_REFUSALS = 21;
/** A condition's expression: text, and it parses. Only the server has the parser. */
const SERVER_ONLY = ['expression must be text', 'check_expression'];
/** Each mirrored rule's wording in the engine, so a renamed or removed rule shows too. */
const MIRRORED = [
  'graph has no nodes', 'duplicate node id', 'has unknown type', 'must name the flow', 'batch_size must be',
  'OnConflict::from_config', 'connector_target', 'map::check', 'has no entry', 'unknown from_node', 'unknown to_node',
  'has no output port', 'has no input port', 'port-type incompatible', 'must have no inbound edges',
  'required input port', 'contains a cycle', 'is unreachable', 'has no reachable Join',
];

function validateBody(): string {
  const src = readFileSync(resolve(process.cwd(), '../crates/engine/attome-workflow/src/graph.rs'), 'utf-8');
  const start = src.indexOf('pub fn validate(graph: &Graph)');
  const end = src.indexOf('#[cfg(test)]', start);
  expect(start).toBeGreaterThan(0);
  expect(end).toBeGreaterThan(start);
  return src.slice(start, end);
}

describe('publishProblems stays in step with the engine\'s validate', () => {
  it('the engine has the refusals the designer knows of', () => {
    const count = validateBody().match(/ValidationError\(/g)?.length ?? 0;
    expect(count).toBe(VALIDATE_REFUSALS);
  });

  it('every mirrored rule is still in the engine', () => {
    const body = validateBody();
    for (const rule of [...MIRRORED, ...SERVER_ONLY]) expect(body, rule).toContain(rule);
  });
});
