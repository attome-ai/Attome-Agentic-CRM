import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * B22-T1: every built-in screen of the signed-in app, read from the route
 * tree itself (`web/src/app/xrm-shell.routes.ts`) so a new screen is checked
 * without anyone listing it. A route counts when it renders a component
 * (`loadComponent` or `component`) at a fixed path: no `:param`, no
 * wildcard, no redirect. Nested paths are joined under `/xrm`.
 *
 * The file is TypeScript, not data, so this reads its object literals by
 * bracket depth rather than importing it (it imports Angular and every
 * screen). Comments are dropped first so a bracket in prose cannot unbalance
 * the walk.
 */
export function xrmStaticRoutes(): string[] {
  const file = join(__dirname, '..', '..', 'web', 'src', 'app', 'xrm-shell.routes.ts');
  let source = readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\n]*/g, '');
  source = source.slice(source.indexOf('export const xrmShellRoutes'));
  const token = /(\{|\}|path:\s*'([^']*)'|redirectTo:|loadComponent:|loadChildren:|component:)/g;
  const stack: { path: string | null; flags: Set<string> }[] = [];
  const found = new Set<string>();
  for (const match of source.matchAll(token)) {
    const t = match[1];
    if (t === '{') {
      stack.push({ path: null, flags: new Set() });
    } else if (t === '}') {
      const node = stack.pop();
      if (!node) break;
      if (node.path === null) continue;
      const parts = ['xrm', ...stack.map(n => n.path).filter((p): p is string => !!p)];
      if (node.path) parts.push(node.path);
      const url = `/${parts.join('/')}`;
      const renders = node.flags.has('loadComponent') || node.flags.has('component');
      if (renders && !node.flags.has('redirectTo') && !url.includes(':') && !url.includes('*')) {
        found.add(url);
      }
    } else if (t.startsWith('path')) {
      const top = stack[stack.length - 1];
      if (top) top.path = match[2];
    } else {
      stack[stack.length - 1]?.flags.add(t.replace(':', ''));
    }
  }
  return [...found].sort();
}
