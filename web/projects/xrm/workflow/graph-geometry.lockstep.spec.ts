import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

// Lockstep guard, same shape as node-config-schema.lockstep.spec.ts.
//
// The graph editor's edge layer never measures the DOM: `portScreenPos` places
// each wire endpoint arithmetically from the node's stored x/y plus a handful
// of module constants (NODE_WIDTH, NODE_BORDER, HEADER_H, PORT_TOP, PORT_H,
// PORT_GAP, PORT_INSET). Those constants describe a card that
// workflow-graph-editor.css is responsible for actually laying out, and the
// failure mode is silent: nudge a padding or a row height in the CSS and every
// wire quietly stops touching its port, which is exactly the bug this pairing
// was introduced to fix.
//
// jsdom has no layout engine, so a rendered getBoundingClientRect() would
// return zeros and prove nothing. Reading both files as text does prove the
// one thing that matters — the two sides still agree on the same numbers.

function source(relPath: string): string {
  // process.cwd() is the angular/ workspace root under the unit-test builder.
  return readFileSync(
    resolve(process.cwd(), 'projects/xrm/workflow/workflow-definition/editor/workflow-graph-editor', relPath),
    'utf-8',
  );
}

const ts  = source('workflow-graph-editor.component.ts');
const css = source('workflow-graph-editor.component.css');

/** Value of a `const NAME = <number>;` in the component module. */
function constant(name: string): number {
  const m = new RegExp(`const ${name}\\s*=\\s*(-?[\\d.]+)\\s*;`).exec(ts);
  expect(m, `component defines const ${name}`).not.toBeNull();
  return Number(m![1]);
}

/** Body of the rule whose selector list is exactly `selector`. */
function rule(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = new RegExp(`(?:^|\\n)${escaped}\\s*\\{([^}]*)\\}`).exec(css);
  expect(m, `css has a rule for "${selector}"`).not.toBeNull();
  return m![1];
}

/** Pixel value of `prop` in `selector`'s rule — first number of the value. */
function px(selector: string, prop: string): number {
  const body = rule(selector);
  const m = new RegExp(`(?:^|[;{\\s])${prop}\\s*:\\s*(-?[\\d.]+)px`).exec(body);
  expect(m, `"${selector}" declares ${prop} in px`).not.toBeNull();
  return Number(m![1]);
}

describe('graph editor node geometry', () => {
  it('NODE_WIDTH matches .node width', () => {
    expect(constant('NODE_WIDTH')).toBe(px('.node', 'width'));
  });

  it('NODE_BORDER matches .node border width', () => {
    expect(constant('NODE_BORDER')).toBe(px('.node', 'border'));
  });

  it('HEADER_H matches .node-header height', () => {
    expect(constant('HEADER_H')).toBe(px('.node-header', 'height'));
  });

  it('PORT_TOP matches .port-col padding-top', () => {
    expect(constant('PORT_TOP')).toBe(px('.port-col', 'padding'));
  });

  it('PORT_GAP matches .port-col gap', () => {
    expect(constant('PORT_GAP')).toBe(px('.port-col', 'gap'));
  });

  it('PORT_H matches .port height', () => {
    expect(constant('PORT_H')).toBe(px('.port', 'height'));
  });

  // The dot straddles the node's border: its box starts inside the border, is
  // pulled back by `left`, and the wire lands on its centre.
  it('PORT_INSET is where .port-dot actually centres on the node edge', () => {
    const inset = px('.node', 'border') + px('.port-dot', 'left') + px('.port-dot', 'width') / 2;
    expect(constant('PORT_INSET')).toBe(inset);
  });

  it('the output dot mirrors the input dot', () => {
    expect(px('.port.output .port-dot', 'right')).toBe(px('.port-dot', 'left'));
  });

  // A header that grows with its content would slide every port below it out
  // from under its wire, which no arithmetic on this side can see coming.
  it('the header clips its label instead of wrapping', () => {
    expect(rule('.node-header .node-title')).toMatch(/white-space:\s*nowrap/);
  });

  // Beziers with a fill flood the canvas.
  it('the edge stroke is unfilled', () => {
    expect(rule('.edge-line')).toMatch(/fill:\s*none/);
  });
});
