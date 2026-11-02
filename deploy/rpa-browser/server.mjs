// M16-T1: the isolated headless browser service. One small HTTP API:
//
//   GET  /health  -> 200 {"ok":true} once the browser is up
//   POST /run     -> runs a step list (steps.mjs) in a fresh browser context
//
// Every run gets a new context: no cookies, storage or cache survive it
// (no persistent profile). Every request the page makes is held to the
// run's allowed_hosts and refused otherwise, so a script reaches only the
// sites it was given. `RPA_TOKEN` (required) must come in the
// `X-Rpa-Token` header; the service listens where the compose file binds it
// (127.0.0.1 by default) and is meant to be called by the Attome server.

import { createServer } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { chromium } from 'playwright';

import { checkRun, hostAllowed } from './steps.mjs';

const PORT = Number(process.env.PORT ?? 8099);
const TOKEN = process.env.RPA_TOKEN ?? '';
const MAX_BODY = 256 * 1024;

if (TOKEN.length < 16) {
  console.error('RPA_TOKEN must be set to at least 16 characters');
  process.exit(1);
}

const browser = await chromium.launch({ headless: true });

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

function authorised(req) {
  const given = Buffer.from(String(req.headers['x-rpa-token'] ?? ''));
  const want = Buffer.from(TOKEN);
  return given.length === want.length && timingSafeEqual(given, want);
}

async function readJson(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error('the body is too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function runSteps({ steps, allowed, timeout }) {
  const context = await browser.newContext({ acceptDownloads: false, serviceWorkers: 'block' });
  const results = [];
  try {
    await context.route('**/*', (route) =>
      hostAllowed(route.request().url(), allowed) ? route.continue() : route.abort('blockedbyclient'));
    const page = await context.newPage();
    page.setDefaultTimeout(Math.min(timeout, 30_000));
    const deadline = Date.now() + timeout;
    for (const [i, step] of steps.entries()) {
      if (Date.now() > deadline) throw new Error(`the run passed its ${timeout} ms`);
      switch (step.kind) {
        case 'goto':
          await page.goto(step.url, { waitUntil: 'domcontentloaded' });
          results.push({ step: i + 1, kind: step.kind, url: page.url() });
          break;
        case 'click':
          await page.click(step.selector);
          results.push({ step: i + 1, kind: step.kind });
          break;
        case 'fill':
          await page.fill(step.selector, step.value);
          results.push({ step: i + 1, kind: step.kind });
          break;
        case 'press':
          await page.press(step.selector, step.key);
          results.push({ step: i + 1, kind: step.kind });
          break;
        case 'wait_for':
          await page.waitForSelector(step.selector);
          results.push({ step: i + 1, kind: step.kind });
          break;
        case 'text':
          results.push({ step: i + 1, kind: step.kind, text: (await page.textContent(step.selector)) ?? null });
          break;
        case 'screenshot':
          results.push({
            step: i + 1, kind: step.kind,
            png_base64: (await page.screenshot({ fullPage: false })).toString('base64'),
          });
          break;
      }
    }
    return { ok: true, results };
  } catch (e) {
    return { ok: false, results, error: String(e?.message ?? e).slice(0, 500) };
  } finally {
    await context.close();
  }
}

createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') return send(res, 200, { ok: browser.isConnected() });
    if (req.method !== 'POST' || req.url !== '/run') return send(res, 404, { error: 'not_found' });
    if (!authorised(req)) return send(res, 401, { error: 'unauthorised' });
    const checked = checkRun(await readJson(req));
    if (!checked.ok) return send(res, 422, { error: checked.error });
    return send(res, 200, await runSteps(checked.run));
  } catch (e) {
    return send(res, 400, { error: String(e?.message ?? e).slice(0, 200) });
  }
}).listen(PORT, () => console.log(`rpa-browser listening on ${PORT}`));
