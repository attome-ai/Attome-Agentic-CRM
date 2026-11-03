import { InjectionToken, Provider, Type } from '@angular/core';

/**
 * F8-T10: a block kind another entry point adds to the page runtime. A page
 * node `{type: 'custom', component: '<name>'}` renders the block registered
 * under that name; `load` imports its component only when a page shows it,
 * so the feature's code stays in the feature's own chunk. The component
 * takes one input, `node` (the page node, its `props` included), and reads
 * the page through `PageContext`.
 */
export interface PageBlock {
  /** The node's `component`, such as `store.product_grid`. */
  component: string;
  load: () => Promise<Type<unknown>>;
}

/** The registered block kinds, one array per `providePageBlocks` call. */
export const PAGE_BLOCKS = new InjectionToken<readonly (readonly PageBlock[])[]>('PAGE_BLOCKS');

/** Registers block kinds for the page runtimes under this injector. */
export function providePageBlocks(blocks: readonly PageBlock[]): Provider {
  return { provide: PAGE_BLOCKS, useValue: blocks, multi: true };
}

/** The block registered under `name`; the last registration wins. Pure. */
export function findBlock(registered: readonly (readonly PageBlock[])[] | null, name: string | undefined): PageBlock | null {
  if (!registered || !name) return null;
  let found: PageBlock | null = null;
  for (const group of registered) for (const block of group) if (block.component === name) found = block;
  return found;
}
