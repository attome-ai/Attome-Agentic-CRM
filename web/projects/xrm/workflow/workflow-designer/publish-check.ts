import {
  outputsOf, portsCompatible, type GraphDoc, type GraphDocNode, type GraphNodeKind,
} from '@attome/xrm/canvas';

/** One thing publishing would refuse. `key` is under `workflowDesigner.problem`. */
export interface PublishProblem {
  /** The node to mark; `null` when the problem is the whole flow's. */
  node: string | null;
  key: string;
  params?: Record<string, string>;
}

const ON_CONFLICT = ['retry_fresh', 'merge', 'stop', 'ask_person'];
const MAX_MAP_FIELDS = 500;

const isPointer = (p: unknown): boolean => typeof p === 'string' && (p === '' || p.startsWith('/'));

/** Mirrors `attome_workflow::map::check`. Pure. */
export function mapConfigOk(config: Record<string, unknown> | undefined): boolean {
  const mapping = config?.['mapping'];
  if (!mapping || typeof mapping !== 'object' || Array.isArray(mapping)) return false;
  const entries = Object.entries(mapping);
  if (entries.length === 0 || entries.length > MAX_MAP_FIELDS) return false;
  for (const [target, source] of entries) {
    if (target.split('.').some(part => part === '')) return false;
    if (typeof source === 'string') {
      if (!isPointer(source)) return false;
    } else if (source && typeof source === 'object' && !Array.isArray(source)) {
      const keys = Object.keys(source);
      const constant = keys.length === 1 && keys[0] === 'value';
      const from = keys.every(k => k === 'from' || k === 'default')
        && isPointer((source as { from?: unknown }).from);
      if (!constant && !from) return false;
    } else {
      return false;
    }
  }
  const each = config?.['each'];
  return each === undefined || each === null || isPointer(each);
}

const named = (v: unknown): boolean => typeof v === 'string' && v.trim() !== '';

/** The settings a node's type checks at publish. Pure. */
function configProblems(node: GraphDocNode): PublishProblem[] {
  const config = node.config;
  const at = (key: string): PublishProblem => ({ node: node.id, key });
  switch (node.type) {
    case 'for_each': {
      // The engine asks only that it is not empty; a connector's names are trimmed.
      const flow = config?.['definition_logicalname'];
      const out = typeof flow === 'string' && flow !== '' ? [] : [at('forEachFlow')];
      const size = config?.['batch_size'];
      if (size !== undefined && !(Number.isInteger(size) && (size as number) >= 1 && (size as number) <= 100)) {
        out.push(at('forEachBatch'));
      }
      return out;
    }
    case 'update_record': {
      const rule = config?.['on_conflict'];
      return rule === undefined || rule === null || (typeof rule === 'string' && ON_CONFLICT.includes(rule))
        ? [] : [at('onConflict')];
    }
    case 'connector':
      return named(config?.['system']) && named(config?.['operation']) ? [] : [at('connector')];
    case 'map':
      return mapConfigOk(config) ? [] : [at('map')];
    default:
      return [];
  }
}

/**
 * M2-T2 — what publishing would refuse, run on every change so a problem shows
 * on its node while the builder edits. Mirrors `attome_workflow::graph::validate`
 * (`publish-check.lockstep.spec.ts` keeps the two together), but lists every
 * problem where the engine stops at the first. Publishing stays the authority:
 * a condition's expression and a module step's settings are only checked there,
 * since they need the expression parser and the deployment's handlers. Pure.
 */
export function publishProblems(doc: GraphDoc, kinds: readonly GraphNodeKind[]): PublishProblem[] {
  if (doc.nodes.length === 0) return [{ node: null, key: 'empty' }];
  const problems: PublishProblem[] = [];
  const kindMap = new Map(kinds.map(k => [k.type, k]));
  const seen = new Set<string>();
  for (const node of doc.nodes) {
    if (seen.has(node.id)) problems.push({ node: node.id, key: 'duplicateId', params: { id: node.id } });
    seen.add(node.id);
    if (!kindMap.has(node.type)) problems.push({ node: node.id, key: 'unknownType', params: { type: node.type } });
    problems.push(...configProblems(node));
  }
  const kindOf = (id: string) => {
    const node = doc.nodes.find(n => n.id === id);
    return node ? kindMap.get(node.type) : undefined;
  };
  const entries = doc.nodes.filter(n => kindMap.get(n.type)?.isEntry).map(n => n.id);
  if (entries.length === 0) problems.push({ node: null, key: 'noEntry' });

  for (const edge of doc.edges) {
    if (!seen.has(edge.from_node)) { problems.push({ node: edge.to_node, key: 'edgeUnknown', params: { id: edge.from_node } }); continue; }
    if (!seen.has(edge.to_node)) { problems.push({ node: edge.from_node, key: 'edgeUnknown', params: { id: edge.to_node } }); continue; }
    const from = kindOf(edge.from_node);
    const to = kindOf(edge.to_node);
    if (!from || !to) continue;
    const out = outputsOf(from).find(p => p.name === edge.from_port);
    if (!out) { problems.push({ node: edge.from_node, key: 'noOutput', params: { port: edge.from_port } }); continue; }
    if (to.isEntry) continue; // Reported below, as an entry's inbound edge.
    const input = to.inputs.find(p => p.name === edge.to_port);
    if (!input) { problems.push({ node: edge.to_node, key: 'noInput', params: { port: edge.to_port } }); continue; }
    if (!portsCompatible(out.portType, input.portType)) {
      problems.push({ node: edge.to_node, key: 'portType', params: { from: out.portType, to: input.portType } });
    }
  }

  for (const node of doc.nodes) {
    const kind = kindMap.get(node.type);
    if (!kind) continue;
    const inbound = doc.edges.filter(e => e.to_node === node.id);
    if (kind.isEntry) {
      if (inbound.length) problems.push({ node: node.id, key: 'entryInbound' });
      continue;
    }
    for (const port of kind.inputs) {
      if (port.required && !inbound.some(e => e.to_port === port.name)) {
        problems.push({ node: node.id, key: 'required', params: { port: port.name } });
      }
    }
  }

  const walk = (start: string[]) => {
    const found = new Set<string>();
    const stack = [...start];
    while (stack.length) {
      const at = stack.pop() as string;
      for (const e of doc.edges) {
        if (e.from_node === at && !found.has(e.to_node)) { found.add(e.to_node); stack.push(e.to_node); }
      }
    }
    return found;
  };

  // A node on a loop reaches itself.
  for (const node of doc.nodes) {
    if (walk([node.id]).has(node.id)) problems.push({ node: node.id, key: 'cycle' });
  }

  if (entries.length) {
    const reachable = walk(entries);
    entries.forEach(e => reachable.add(e));
    for (const node of doc.nodes) {
      if (!reachable.has(node.id)) problems.push({ node: node.id, key: 'unreachable' });
    }
  }

  for (const node of doc.nodes) {
    if (node.type !== 'split') continue;
    const downstream = walk([node.id]);
    if (![...downstream].some(id => doc.nodes.find(n => n.id === id)?.type === 'join')) {
      problems.push({ node: node.id, key: 'split' });
    }
  }
  return problems;
}
