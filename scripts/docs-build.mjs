#!/usr/bin/env node
// AC9-T1: builds the documentation site: static HTML, one folder per
// version, English and Arabic (right to left), and an API reference made
// from openapi.json. No dependencies beyond Node 22.
//
//   node scripts/docs-build.mjs                 # target/docs-site/<version>/{en,ar}/
//   node scripts/docs-build.mjs --out <dir>     # somewhere else
//   node scripts/docs-build.mjs --version 2.0.0 # name the version (default: Cargo.toml's)
//
// English pages are docs/**/*.md; an Arabic page is the same path under
// docs/ar/. A page with no Arabic yet is shown in English on the Arabic
// site, marked as untranslated. Links between .md files become links between
// the built pages. versions.json at the top lists every version built into
// the output folder, so earlier releases stay browsable side by side.

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const arg = name => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const version =
  arg('--version') ??
  (readFileSync(join(root, 'Cargo.toml'), 'utf8').match(/^version\s*=\s*"([^"]+)"/m) ?? [])[1] ??
  'dev';
const out = arg('--out') ?? join(root, 'target', 'docs-site');
const docsDir = join(root, 'docs');
const SKIP_DIRS = new Set(['ar', 'evidence', 'perf-history', 'dependencies']);

const UI = {
  en: {
    dir: 'ltr', title: 'Attome documentation', api: 'API reference', home: 'Documentation',
    untranslated: '', other: 'العربية', version: 'Version', params: 'Parameters', body: 'Request body',
    responses: 'Responses', name: 'Name', in: 'In', required: 'Required', description: 'Description',
    status: 'Status', yes: 'yes', no: 'no', operations: 'operations',
  },
  ar: {
    dir: 'rtl', title: 'وثائق Attome', api: 'مرجع الواجهة البرمجية', home: 'الوثائق',
    untranslated: 'لم تُترجم هذه الصفحة إلى العربية بعد؛ هذا نصها الإنجليزي.', other: 'English',
    version: 'الإصدار', params: 'المعاملات', body: 'جسم الطلب', responses: 'الاستجابات', name: 'الاسم',
    in: 'الموضع', required: 'مطلوب', description: 'الوصف', status: 'الحالة', yes: 'نعم', no: 'لا',
    operations: 'عمليات',
  },
};

// ── Markdown ────────────────────────────────────────────────────────────────

export function escapeHtml(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function slug(text) {
  return text
    .toLowerCase()
    .replace(/<[^>]+>/g, '')
    .replace(/[^\p{L}\p{N}\s-]/gu, '')
    .trim()
    .replace(/\s+/g, '-');
}

/** Inline markdown: code, links, bold, italic; `.md` links point at `.html`. */
export function inline(text) {
  const codes = [];
  let s = text.replace(/`([^`]+)`/g, (_, code) => {
    codes.push(`<code>${escapeHtml(code)}</code>`);
    return `\u0000${codes.length - 1}\u0000`;
  });
  s = escapeHtml(s);
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (_, label, href) => {
    const target = /^[a-z]+:/i.test(href) || href.startsWith('#')
      ? href
      : href.replace(/\.md(#|$)/, '.html$1').replace(/\/$/, '/index.html');
    return `<a href="${target}">${label}</a>`;
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/(^|[^*])\*([^*\s][^*]*)\*/g, '$1<em>$2</em>');
  return s.replace(/\u0000(\d+)\u0000/g, (_, i) => codes[Number(i)]);
}

/** Block markdown to HTML: headings, paragraphs, lists, code, tables, quotes, rules. */
export function markdown(source) {
  const lines = source.replace(/\r\n/g, '\n').split('\n');
  const html = [];
  let i = 0;
  const isBlockStart = l =>
    /^(#{1,6})\s/.test(l) || /^```/.test(l) || /^\s*([-*]|\d+\.)\s/.test(l) || /^\|/.test(l) || /^>/.test(l) || /^---+\s*$/.test(l);
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    let m;
    if ((m = line.match(/^(#{1,6})\s+(.*)$/))) {
      const level = m[1].length;
      html.push(`<h${level} id="${slug(m[2])}">${inline(m[2])}</h${level}>`);
      i++;
    } else if (/^```/.test(line)) {
      const lang = line.slice(3).trim();
      const body = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) body.push(lines[i++]);
      i++;
      html.push(`<pre dir="ltr"><code${lang ? ` class="language-${escapeHtml(lang)}"` : ''}>${escapeHtml(body.join('\n'))}</code></pre>`);
    } else if (/^---+\s*$/.test(line)) {
      html.push('<hr>');
      i++;
    } else if (/^>/.test(line)) {
      const body = [];
      while (i < lines.length && /^>/.test(lines[i])) body.push(lines[i++].replace(/^>\s?/, ''));
      html.push(`<blockquote>${markdown(body.join('\n'))}</blockquote>`);
    } else if (/^\|/.test(line)) {
      const rows = [];
      while (i < lines.length && /^\|/.test(lines[i])) rows.push(lines[i++]);
      const cells = r => r.replace(/^\||\|\s*$/g, '').split('|').map(c => c.trim());
      const head = cells(rows[0]);
      const body = rows.slice(/^\|[\s:|-]+\|?\s*$/.test(rows[1] ?? '') ? 2 : 1);
      html.push(
        '<table><thead><tr>' + head.map(c => `<th>${inline(c)}</th>`).join('') + '</tr></thead><tbody>' +
          body.map(r => '<tr>' + cells(r).map(c => `<td>${inline(c)}</td>`).join('') + '</tr>').join('') +
          '</tbody></table>',
      );
    } else if (/^\s*([-*]|\d+\.)\s/.test(line)) {
      const ordered = /^\s*\d+\./.test(line);
      const items = [];
      while (i < lines.length && lines[i].trim() && (/^\s*([-*]|\d+\.)\s/.test(lines[i]) || /^\s{2,}\S/.test(lines[i]))) {
        if (/^\s*([-*]|\d+\.)\s/.test(lines[i]) && !/^\s{2,}/.test(lines[i])) items.push(lines[i].replace(/^\s*([-*]|\d+\.)\s+/, ''));
        else if (items.length) items[items.length - 1] += '\n' + lines[i].replace(/^\s{2,}/, '');
        i++;
      }
      const tag = ordered ? 'ol' : 'ul';
      html.push(`<${tag}>` + items.map(it => {
        const [first, ...rest] = it.split('\n');
        return `<li>${inline(first)}${rest.length ? markdown(rest.join('\n')) : ''}</li>`;
      }).join('') + `</${tag}>`);
    } else {
      const para = [];
      while (i < lines.length && lines[i].trim() && !isBlockStart(lines[i])) para.push(lines[i++]);
      html.push(`<p>${inline(para.join(' '))}</p>`);
    }
  }
  return html.join('\n');
}

// ── Pages ───────────────────────────────────────────────────────────────────

function walk(dir, base = dir, outList = []) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      if (dir === base && SKIP_DIRS.has(name)) continue;
      walk(path, base, outList);
    } else if (name.endsWith('.md')) {
      outList.push(relative(base, path).split(sep).join('/'));
    }
  }
  return outList;
}

const titleOf = (source, fallback) => (source.match(/^#\s+(.+)$/m) ?? [])[1] ?? fallback;
const htmlPath = rel => rel.replace(/README\.md$/, 'index.md').replace(/\.md$/, '.html');
const up = rel => '../'.repeat(rel.split('/').length - 1);

const STYLE = `
:root { color-scheme: light dark; --fg: #1f2328; --muted: #59636e; --bg: #fff; --line: #d1d9e0; --accent: #0969da; }
@media (prefers-color-scheme: dark) { :root { --fg: #e6edf3; --muted: #9198a1; --bg: #0d1117; --line: #3d444d; --accent: #4493f8; } }
body { margin: 0; font: 16px/1.6 system-ui, "Segoe UI", "Noto Sans Arabic", sans-serif; color: var(--fg); background: var(--bg); }
header { display: flex; gap: 1rem; align-items: center; padding-block: .75rem; padding-inline: 1.5rem; border-block-end: 1px solid var(--line); flex-wrap: wrap; }
header a { color: var(--accent); text-decoration: none; } header .spacer { flex: 1; }
.wrap { display: flex; gap: 2rem; padding-inline: 1.5rem; }
nav { flex: 0 0 15rem; padding-block: 1rem; font-size: .9rem; } nav ul { list-style: none; padding: 0; margin: 0; }
nav li { margin-block: .25rem; } nav a { color: var(--fg); text-decoration: none; } nav a:hover { color: var(--accent); }
main { flex: 1; min-inline-size: 0; padding-block: 1rem 4rem; max-inline-size: 52rem; }
main a { color: var(--accent); }
pre { overflow-x: auto; padding: .75rem; border: 1px solid var(--line); border-radius: .375rem; text-align: start; }
code { font-family: ui-monospace, "Cascadia Code", monospace; font-size: .9em; }
table { border-collapse: collapse; margin-block: 1rem; } th, td { border: 1px solid var(--line); padding-block: .25rem; padding-inline: .5rem; text-align: start; vertical-align: top; }
blockquote { margin-inline: 0; padding-inline-start: 1rem; border-inline-start: 3px solid var(--line); color: var(--muted); }
.note { padding: .5rem .75rem; border: 1px solid var(--line); border-radius: .375rem; color: var(--muted); }
.op { border-block-start: 1px solid var(--line); padding-block-start: 1rem; margin-block-start: 1.5rem; }
.method { font-weight: 700; text-transform: uppercase; margin-inline-end: .5rem; }
@media (max-width: 48rem) { .wrap { flex-direction: column; } nav { flex: none; } }
`;

function layout({ lang, rel, title, body, nav }) {
  const ui = UI[lang];
  const other = lang === 'en' ? 'ar' : 'en';
  const back = up(rel);
  return `<!doctype html>
<html lang="${lang}" dir="${ui.dir}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} · ${ui.title}</title>
<link rel="stylesheet" href="${back}style.css">
</head>
<body>
<header>
<a href="${back}index.html"><strong>${ui.title}</strong></a>
<a href="${back}api/index.html">${ui.api}</a>
<span class="spacer"></span>
<span>${ui.version} ${escapeHtml(version)}</span>
<a href="${back}../${other}/${rel}" lang="${other}">${UI[lang].other}</a>
</header>
<div class="wrap">
<nav aria-label="${ui.home}"><ul>${nav.map(p => `<li><a href="${back}${p.href}">${escapeHtml(p.title)}</a></li>`).join('')}</ul></nav>
<main>
${body}
</main>
</div>
</body>
</html>
`;
}

function write(path, text) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}

// ── API reference ───────────────────────────────────────────────────────────

const METHODS = ['get', 'put', 'post', 'patch', 'delete'];

export function apiByTag(doc) {
  const tags = new Map();
  for (const [path, item] of Object.entries(doc.paths ?? {})) {
    for (const method of METHODS) {
      const op = item?.[method];
      if (!op) continue;
      const tag = op.tags?.[0] ?? 'other';
      if (!tags.has(tag)) tags.set(tag, []);
      tags.get(tag).push({ method, path, op });
    }
  }
  for (const ops of tags.values()) ops.sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method));
  return new Map([...tags.entries()].sort(([a], [b]) => a.localeCompare(b)));
}

const refName = schema => {
  if (!schema) return '';
  if (schema.$ref) return schema.$ref.split('/').pop();
  if (schema.type === 'array') return `${refName(schema.items)}[]`;
  return schema.type ?? 'object';
};

function operationHtml({ method, path, op }, ui) {
  const params = (op.parameters ?? []).filter(p => !p.$ref);
  const body = op.requestBody?.content?.['application/json']?.schema;
  const responses = Object.entries(op.responses ?? {});
  return `<section class="op" id="${slug(`${method} ${path}`)}">
<h2 dir="ltr"><span class="method">${method}</span><code>${escapeHtml(path)}</code></h2>
${op.summary ? `<p><strong>${escapeHtml(op.summary)}</strong></p>` : ''}
${op.description ? markdown(op.description) : ''}
${params.length ? `<h3>${ui.params}</h3><table><thead><tr><th>${ui.name}</th><th>${ui.in}</th><th>${ui.required}</th><th>${ui.description}</th></tr></thead><tbody>${params
    .map(p => `<tr><td dir="ltr"><code>${escapeHtml(p.name)}</code></td><td>${escapeHtml(p.in)}</td><td>${p.required ? ui.yes : ui.no}</td><td>${inline(p.description ?? '')}</td></tr>`)
    .join('')}</tbody></table>` : ''}
${body ? `<h3>${ui.body}</h3><p dir="ltr"><code>${escapeHtml(refName(body))}</code></p>` : ''}
${responses.length ? `<h3>${ui.responses}</h3><table><thead><tr><th>${ui.status}</th><th>${ui.description}</th></tr></thead><tbody>${responses
    .map(([code, r]) => `<tr><td dir="ltr">${escapeHtml(code)}</td><td>${inline(r.description ?? '')}</td></tr>`)
    .join('')}</tbody></table>` : ''}
</section>`;
}

// ── Build ───────────────────────────────────────────────────────────────────

function build() {
  const english = walk(docsDir).sort();
  const arabicDir = join(docsDir, 'ar');
  const arabic = new Set(existsSync(arabicDir) ? walk(arabicDir) : []);
  const openapi = JSON.parse(readFileSync(join(root, 'openapi.json'), 'utf8'));
  const tags = apiByTag(openapi);
  const site = join(out, version);
  let pages = 0;

  for (const lang of ['en', 'ar']) {
    const ui = UI[lang];
    const sources = new Map(english.map(rel => {
      const translated = lang === 'ar' && arabic.has(rel);
      const text = readFileSync(join(translated ? arabicDir : docsDir, rel), 'utf8');
      return [rel, { text, translated: lang === 'en' || translated }];
    }));
    const nav = english
      .filter(rel => !rel.includes('/') || rel.endsWith('README.md'))
      .map(rel => ({ href: htmlPath(rel), title: titleOf(sources.get(rel).text, rel) }));
    for (const rel of english) {
      const { text, translated } = sources.get(rel);
      const outRel = htmlPath(rel);
      const note = !translated ? `<p class="note">${ui.untranslated}</p><div lang="en" dir="ltr">` : '';
      const body = note + markdown(text) + (note ? '</div>' : '');
      write(join(site, lang, outRel), layout({ lang, rel: outRel, title: titleOf(text, rel), body, nav }));
      pages++;
    }
    const apiNav = [...tags.keys()].map(tag => ({ href: `api/${slug(tag) || 'other'}.html`, title: tag }));
    const index = `<h1>${ui.api}</h1><ul>${[...tags.entries()]
      .map(([tag, ops]) => `<li><a href="${slug(tag) || 'other'}.html" dir="ltr">${escapeHtml(tag)}</a> (${ops.length} ${ui.operations})</li>`)
      .join('')}</ul>`;
    write(join(site, lang, 'api', 'index.html'), layout({ lang, rel: 'api/index.html', title: ui.api, body: index, nav: apiNav }));
    for (const [tag, ops] of tags) {
      const rel = `api/${slug(tag) || 'other'}.html`;
      const body = `<h1 dir="ltr">${escapeHtml(tag)}</h1>` + ops.map(o => operationHtml(o, ui)).join('\n');
      write(join(site, lang, rel), layout({ lang, rel, title: tag, body, nav: apiNav }));
      pages++;
    }
    write(join(site, lang, 'style.css'), STYLE);
  }

  write(join(site, 'index.html'), `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=en/index.html"><a href="en/index.html">${UI.en.title}</a>\n`);
  const versionsFile = join(out, 'versions.json');
  const versions = existsSync(versionsFile) ? JSON.parse(readFileSync(versionsFile, 'utf8')) : [];
  if (!versions.includes(version)) versions.push(version);
  versions.sort((a, b) => b.localeCompare(a, undefined, { numeric: true }));
  write(versionsFile, JSON.stringify(versions, null, 2) + '\n');
  write(join(out, 'index.html'), `<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0; url=${versions[0]}/en/index.html"><a href="${versions[0]}/en/index.html">${UI.en.title}</a>\n`);
  console.log(`docs-build: ${pages} pages for version ${version} in ${relative(root, site) || site}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) build();
