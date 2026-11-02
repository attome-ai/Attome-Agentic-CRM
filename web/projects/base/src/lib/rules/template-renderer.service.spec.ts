import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { TestBed } from '@angular/core/testing';
import { describe, expect, it } from 'vitest';
import { TEMPLATE_WASM_SOURCE, TemplateRendererService } from './template-renderer.service';

// The committed module (scripts/build-html-wasm.ps1 writes it), read from disk.
const WASM = resolve(process.cwd(), 'projects/base/src/lib/rules/html-wasm/attome_html_wasm_bg.wasm');

function service(): TemplateRendererService {
  TestBed.configureTestingModule({
    providers: [{ provide: TEMPLATE_WASM_SOURCE, useValue: async () => readFileSync(WASM) }],
  });
  return TestBed.inject(TemplateRendererService);
}

const schema = { fields: { name: 'text', total: 'number' } };
const context = { now: '2026-11-02T09:00:00Z', fields: { name: '<Acme>', total: 1250.5 } };

describe('TemplateRendererService', () => {
  it('preview output equals the server output for a fixture template', async () => {
    // The server's render of this template, from attome-html-wasm's parity test.
    const answer = await service().render(
      '<h1>{{ name }}</h1>{% if total > 100 %}big{% else %}small{% end %}',
      schema,
      context,
      'en',
    );
    expect(answer).toEqual({ ok: true, output: '<h1>&lt;Acme&gt;</h1>big' });
  });

  it('answers a template error rather than throwing', async () => {
    const answer = await service().render('{{ missing }}', schema, context, 'en');
    expect(answer.ok).toBe(false);
    expect(answer.diagnostics?.length).toBe(1);
  });
});
