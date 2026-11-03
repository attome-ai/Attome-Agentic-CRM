import { type APIRequestContext, expect, test } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * AK1-T1: time to a working CRM. Against a live deployment, the steps a new
 * customer takes: install (until the server answers ready), the first-run
 * country, describing an app to the building agent (`model.app.plan`),
 * drafting a model from a spreadsheet (`model.from_files`) and making its
 * build calls, importing the spreadsheet, and opening the records.
 *
 * Run it against a deployment whose model is the fake model (the AD4
 * fixtures), so the answers are deterministic:
 *
 *   ATTOME_E2E_URL=http://127.0.0.1:7865 ATTOME_E2E_AUTH="ApiKey <id>:<secret>" \
 *     npx playwright test -c time-to-crm.config.ts
 *
 * `ATTOME_E2E_INSTALL_STARTED` (epoch milliseconds) is when the installer
 * began; without it the install step times the wait for readiness alone.
 * Without `ATTOME_E2E_URL` the spec is skipped.
 *
 * Every step's duration, and how much of it the model took, goes to
 * `results/time-to-crm.json`. The run fails above 60 minutes in all, model
 * latency excluded.
 */

const URL = process.env['ATTOME_E2E_URL'] ?? '';
const AUTH = process.env['ATTOME_E2E_AUTH'] ?? '';
const INSTALL_STARTED = Number(process.env['ATTOME_E2E_INSTALL_STARTED'] ?? '');
const LIMIT_MS = 60 * 60 * 1000;
const RESULTS = join(__dirname, 'results', 'time-to-crm.json');

interface Step { name: string; ms: number; model_ms: number }

/** The spreadsheet a customer brings: one sheet of clinic visits. */
function sheet(name: string): { name: string; csv: string } {
  const rows = ['code,patient,visit_date,fee'];
  for (let i = 1; i <= 50; i++) {
    rows.push(`V${String(i).padStart(4, '0')},Patient ${i},2026-0${(i % 9) + 1}-1${i % 10},${100 + i}.00`);
  }
  return { name, csv: `${rows.join('\n')}\n` };
}

test.describe.configure({ mode: 'serial' });

test('a new customer reaches a working CRM within an hour', async ({ playwright }) => {
  test.skip(!URL, 'ATTOME_E2E_URL is not set: no deployment to run against');
  test.setTimeout(LIMIT_MS + 5 * 60 * 1000);

  const api: APIRequestContext = await playwright.request.newContext({
    baseURL: URL,
    extraHTTPHeaders: { authorization: AUTH, origin: URL },
  });
  const steps: Step[] = [];
  async function step(name: string, run: () => Promise<number>): Promise<void> {
    const start = Date.now();
    const model_ms = await run();
    steps.push({ name, ms: Date.now() - start, model_ms });
  }
  /** An action's answer, and how long the call took (the model's share). */
  async function invoke(action: string, args: unknown): Promise<{ result: Record<string, unknown>; ms: number }> {
    const start = Date.now();
    const res = await api.post(`/api/v1/actions/${action}/invoke`, { data: { args } });
    expect(res.ok(), `${action}: ${res.status()} ${await res.text()}`).toBeTruthy();
    const body = (await res.json()) as { result: Record<string, unknown> };
    return { result: body.result, ms: Date.now() - start };
  }
  async function until(path: string, done: (body: Record<string, unknown>) => boolean): Promise<Record<string, unknown>> {
    for (;;) {
      const res = await api.get(path);
      expect(res.ok(), `${path}: ${res.status()}`).toBeTruthy();
      const body = (await res.json()) as Record<string, unknown>;
      if (done(body)) return body;
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  // Install: from the installer's start (or this run's) until the server answers ready.
  const runStart = Date.now();
  const installStart = Number.isFinite(INSTALL_STARTED) && INSTALL_STARTED > 0 ? INSTALL_STARTED : runStart;
  for (;;) {
    const res = await api.get('/health/ready').catch(() => null);
    if (res?.ok()) break;
    await new Promise(r => setTimeout(r, 1000));
  }
  steps.push({ name: 'install', ms: Date.now() - installStart, model_ms: 0 });

  await step('first-run country', async () => {
    const res = await api.post('/api/v1/admin/setup/region', { data: { country: 'SA', language: 'ar' } });
    expect(res.ok(), `region: ${res.status()} ${await res.text()}`).toBeTruthy();
    return 0;
  });

  await step('describe an app', async () => {
    const description = 'A clinic: patients book visits, the front desk records each visit and its fee.';
    const draft = await invoke('model.app.plan', { description, confirmed: false });
    expect(draft.result['written_plan']).toBeTruthy();
    const confirmed = await invoke('model.app.plan', { description, confirmed: true });
    return draft.ms + confirmed.ms;
  });

  const suffix = Date.now().toString(36);
  const file = sheet(`Visits ${suffix}`);
  let entity = '';
  let mapping: Record<string, unknown> = {};

  await step('model from the spreadsheet', async () => {
    const drafted = await invoke('model.from_files', { files: [file] });
    const imports = drafted.result['imports'] as { entity: string; options: { mapping: Record<string, unknown> } }[];
    expect(imports.length).toBe(1);
    entity = imports[0].entity;
    mapping = imports[0].options.mapping;
    for (const call of drafted.result['calls'] as { action: string; args: unknown }[]) {
      await invoke(call.action, call.args);
    }
    // The build calls do not reach the model: only the draft's labelling does.
    return drafted.ms;
  });

  await step('import the spreadsheet', async () => {
    const res = await api.post(`/api/v1/${entity}/imports`, {
      multipart: {
        file: { name: `${file.name}.csv`, mimeType: 'text/csv', buffer: Buffer.from(file.csv, 'utf8') },
        options: JSON.stringify({ mapping, match_mode: 'create' }),
      },
    });
    expect(res.status(), await res.text()).toBeLessThan(300);
    const { job_id } = (await res.json()) as { job_id: string };
    await until(`/api/v1/${entity}/imports/${job_id}`, b => ['staged', 'validated', 'failed'].includes(String(b['status'])));
    const apply = await api.post(`/api/v1/${entity}/imports/${job_id}/apply`);
    expect(apply.status(), await apply.text()).toBe(202);
    const job = await until(`/api/v1/${entity}/imports/${job_id}`, b => ['applied', 'failed'].includes(String(b['status'])));
    expect(job['status'], JSON.stringify(job['counts'])).toBe('applied');
    return 0;
  });

  await step('open the records', async () => {
    const res = await api.get(`/api/v1/${entity}?page=1&page_size=50`);
    expect(res.ok(), `${res.status()} ${await res.text()}`).toBeTruthy();
    const page = (await res.json()) as { total: number };
    expect(page.total).toBe(50);
    return 0;
  });

  const total_ms = steps.reduce((sum, s) => sum + s.ms, 0);
  const model_ms = steps.reduce((sum, s) => sum + s.model_ms, 0);
  const measured_ms = total_ms - model_ms;
  mkdirSync(join(__dirname, 'results'), { recursive: true });
  writeFileSync(RESULTS, `${JSON.stringify({ steps, total_ms, model_ms, measured_ms, limit_ms: LIMIT_MS }, null, 2)}\n`);
  await api.dispose();
  expect(measured_ms, 'time to a working CRM, model latency excluded').toBeLessThanOrEqual(LIMIT_MS);
});
