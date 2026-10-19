// AC9-T1: the docs site's renderer. Run with `node --test scripts/docs-build.test.mjs`.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { apiByTag, escapeHtml, inline, markdown, slug } from './docs-build.mjs';

test('headings get ids, and Arabic headings keep their letters', () => {
  assert.equal(markdown('# Data layer'), '<h1 id="data-layer">Data layer</h1>');
  assert.equal(slug('التقويم الهجري'), 'التقويم-الهجري');
});

test('links to .md pages become .html, outside links stay', () => {
  assert.equal(inline('[Hijri](hijri.md)'), '<a href="hijri.html">Hijri</a>');
  assert.equal(inline('[x](a.md#part)'), '<a href="a.html#part">x</a>');
  assert.equal(inline('[site](https://attome.com)'), '<a href="https://attome.com">site</a>');
});

test('text is escaped, code is kept verbatim', () => {
  assert.equal(inline('a <b> `x < y`'), 'a &lt;b&gt; <code>x &lt; y</code>');
  assert.equal(escapeHtml('"&'), '&quot;&amp;');
  assert.match(markdown('```sh\necho <x>\n```'), /<pre dir="ltr"><code class="language-sh">echo &lt;x&gt;<\/code><\/pre>/);
});

test('lists, tables and quotes', () => {
  assert.equal(markdown('- one\n- two'), '<ul><li>one</li><li>two</li></ul>');
  assert.equal(markdown('1. a\n2. b'), '<ol><li>a</li><li>b</li></ol>');
  assert.equal(
    markdown('| a | b |\n|---|---|\n| 1 | 2 |'),
    '<table><thead><tr><th>a</th><th>b</th></tr></thead><tbody><tr><td>1</td><td>2</td></tr></tbody></table>',
  );
  assert.equal(markdown('> said'), '<blockquote><p>said</p></blockquote>');
});

test('the API reference groups operations by their first tag', () => {
  const doc = {
    paths: {
      '/api/v1/b': { get: { tags: ['jobs'] }, post: { tags: ['jobs'] } },
      '/api/v1/a': { delete: { tags: ['admin'] } },
      '/api/v1/c': { get: {} },
    },
  };
  const tags = apiByTag(doc);
  assert.deepEqual([...tags.keys()], ['admin', 'jobs', 'other']);
  assert.deepEqual(tags.get('jobs').map(o => o.method), ['get', 'post']);
});
