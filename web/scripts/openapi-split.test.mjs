// S2-T15: node --test web/scripts/openapi-split.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { qualityReport, splitByModule } from './openapi-split.mjs';

const doc = {
  openapi: '3.1.0',
  info: { title: 'Attome', version: '2.0.0' },
  tags: [{ name: 'entity' }, { name: 'sales' }],
  paths: {
    '/api/v1/{entity}': {
      get: {
        'x-module': 'core',
        tags: ['entity'],
        summary: 'List records',
        responses: {
          200: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Page' } } } },
        },
      },
    },
    '/api/v1/sales/quotes': {
      post: {
        'x-module': 'sales',
        tags: ['sales'],
        requestBody: {
          content: { 'application/json': { schema: { $ref: '#/components/schemas/Quote' }, example: {} } },
        },
        responses: { 201: { description: 'made' } },
      },
    },
  },
  components: {
    schemas: {
      Page: { type: 'object', properties: { items: { type: 'array', items: { $ref: '#/components/schemas/Row' } } } },
      Row: { type: 'object' },
      Quote: { type: 'object', properties: { line: { $ref: '#/components/schemas/Line' } } },
      Line: { type: 'object' },
      Unused: { type: 'object' },
    },
    securitySchemes: { api_key: { type: 'apiKey', in: 'header', name: 'Authorization' } },
  },
};

test('module split keeps referenced schemas', () => {
  const parts = splitByModule(doc);
  assert.deepEqual([...parts.keys()], ['core', 'sales']);
  const core = parts.get('core');
  assert.deepEqual(Object.keys(core.paths), ['/api/v1/{entity}']);
  assert.deepEqual(Object.keys(core.components.schemas), ['Page', 'Row'], 'Row is reached through Page');
  assert.deepEqual(core.tags, [{ name: 'entity' }]);
  assert.ok(core.components.securitySchemes.api_key);
  const sales = parts.get('sales');
  assert.deepEqual(Object.keys(sales.components.schemas), ['Line', 'Quote']);
  assert.ok(!('Unused' in sales.components.schemas));
});

test('the quality report counts summaries, descriptions and examples', () => {
  const report = qualityReport(doc, { arabicTranslated: 1, lintBaselineEntries: 7 });
  assert.deepEqual(report, {
    release: '2.0.0',
    operations: 2,
    with_summary: 1,
    with_description: 0,
    with_example: 1,
    arabic_translated: 1,
    lint_baseline_entries: 7,
  });
});
