// S2-T15: the OpenAPI document split by module, and its quality report.
// Pure functions over a parsed document; generate-api-types.mjs writes what
// they return, and openapi-split.test.mjs tests them.
//
// A module's document holds the operations whose `x-module` names it and the
// components they reach through `$ref`, walked transitively, with the
// document's own `openapi`, `info`, `x-api-version`, security schemes and the
// tags its operations use. Webhooks and version adapters stay in the full
// document only.

const METHODS = new Set(['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace']);

/** Every `#/components/...` reference under `node`, into `out`. */
function collectRefs(node, out) {
  if (Array.isArray(node)) {
    for (const item of node) collectRefs(item, out);
  } else if (node && typeof node === 'object') {
    if (typeof node.$ref === 'string' && node.$ref.startsWith('#/components/')) out.add(node.$ref);
    for (const value of Object.values(node)) collectRefs(value, out);
  }
}

/** `{kind, name}` of a `#/components/<kind>/<name>` reference. */
function parseRef(ref) {
  const [, , kind, ...rest] = ref.split('/');
  return { kind, name: rest.join('/') };
}

function sortedObject(object) {
  return Object.fromEntries(Object.entries(object).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

/** The operations of `doc`, as `[path, method, operation]`. */
export function operations(doc) {
  const out = [];
  for (const [path, item] of Object.entries(doc.paths ?? {})) {
    for (const [method, op] of Object.entries(item ?? {})) {
      if (METHODS.has(method) && op && typeof op === 'object') out.push([path, method, op]);
    }
  }
  return out;
}

/** One document per `x-module`, as a Map from module name to document. */
export function splitByModule(doc) {
  const byModule = new Map();
  for (const [path, method, op] of operations(doc)) {
    const module = op['x-module'];
    if (typeof module !== 'string' || !module) continue;
    if (!byModule.has(module)) byModule.set(module, {});
    const paths = byModule.get(module);
    paths[path] ??= {};
    paths[path][method] = op;
  }
  const components = doc.components ?? {};
  const result = new Map();
  for (const [module, paths] of [...byModule.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const pending = new Set();
    collectRefs(paths, pending);
    const seen = new Set();
    const picked = {};
    while (pending.size) {
      const [ref] = pending;
      pending.delete(ref);
      if (seen.has(ref)) continue;
      seen.add(ref);
      const { kind, name } = parseRef(ref);
      const value = components[kind]?.[name];
      if (value === undefined) continue;
      picked[kind] ??= {};
      picked[kind][name] = value;
      const more = new Set();
      collectRefs(value, more);
      for (const next of more) if (!seen.has(next)) pending.add(next);
    }
    const tagNames = new Set();
    for (const item of Object.values(paths)) {
      for (const op of Object.values(item)) for (const tag of op.tags ?? []) tagNames.add(tag);
    }
    const part = {
      openapi: doc.openapi,
      info: doc.info,
      ...(doc['x-api-version'] !== undefined ? { 'x-api-version': doc['x-api-version'] } : {}),
      paths: sortedObject(paths),
      components: {
        ...Object.fromEntries(Object.entries(picked).map(([kind, values]) => [kind, sortedObject(values)])),
        ...(components.securitySchemes ? { securitySchemes: components.securitySchemes } : {}),
      },
      tags: (doc.tags ?? []).filter((tag) => tagNames.has(tag.name)),
    };
    result.set(module, part);
  }
  return result;
}

/** Whether an operation carries a request or response example. */
function hasExample(op) {
  const contents = [
    ...Object.values(op.requestBody?.content ?? {}),
    ...Object.values(op.responses ?? {}).flatMap((r) => Object.values(r?.content ?? {})),
  ];
  return contents.some((c) => c && (c.example !== undefined || c.examples !== undefined));
}

/**
 * The quality report: how many operations carry a summary, a description and
 * an example, how many have Arabic text, and the lint baseline's size.
 */
export function qualityReport(doc, { arabicTranslated = 0, lintBaselineEntries = 0 } = {}) {
  const ops = operations(doc).map(([, , op]) => op);
  const count = (test) => ops.filter(test).length;
  return {
    release: doc.info?.version ?? null,
    operations: ops.length,
    with_summary: count((op) => typeof op.summary === 'string' && op.summary.trim() !== ''),
    with_description: count((op) => typeof op.description === 'string' && op.description.trim() !== ''),
    with_example: count(hasExample),
    arabic_translated: arabicTranslated,
    lint_baseline_entries: lintBaselineEntries,
  };
}

/** The report's shares as console lines. */
export function qualityLines(report) {
  const share = (n) => (report.operations ? `${((100 * n) / report.operations).toFixed(1)}%` : 'n/a');
  return [
    `openapi quality: ${report.operations} operations`,
    `  summary ${share(report.with_summary)}, description ${share(report.with_description)}, ` +
      `example ${share(report.with_example)}, Arabic ${share(report.arabic_translated)}`,
    `  lint baseline: ${report.lint_baseline_entries} entries`,
  ];
}
