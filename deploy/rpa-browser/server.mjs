// M16-T1: the isolated headless browser service. One small HTTP API:
//
//   GET  /health  -> 200 {"ok":true} once the browser is up
//   POST /run     -> runs a step list (steps.mjs) in a fresh browser context
//
// M16-T3, recording by showing (recorder.mjs): a recording is a live page
// the Attome editor drives by its screenshots; each action answers the step
// it recorded and the page as it now looks.
//
//   POST   /record            {url, allowed_hosts} -> {session, step, png_base64}
//   POST   /record/<id>/click {x, y}               -> {step, password, png_base64}
//   POST   /record/<id>/type  {text}               -> {step, png_base64}
//   POST   /record/<id>/press {key}                -> {step, png_base64}
//   DELETE /record/<id>                            -> 204
//
// A typed value lands in the step except in a password field, where the
// step holds `{{secret:password}}` and the text is only typed into the page.
//
// Every run gets a new context: no cookies, storage or cache survive it
// (no persistent profile). Every request the page makes is held to the
// run's allowed_hosts and refused otherwise, so a script reaches only the
// sites it was given. `RPA_TOKEN` (required) must come in the
// `X-Rpa-Token` header; the service listens where the compose file binds it
// (127.0.0.1 by default) and is meant to be called by the Attome server.

import { createServer } from 'node:http';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { chromium } from 'playwright';

import { ELEMENT_INFO, IDLE_MS, MAX_SESSIONS, VIEWPORT, checkStart, pointOk, selectorFor } from './recorder.mjs';
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

/** Open recordings: id -> { context, page, focused, password, touched }. */
const sessions = new Map();

async function closeSession(id) {
  const session = sessions.get(id);
  sessions.delete(id);
  if (session) await session.context.close().catch(() => {});
}

setInterval(() => {
  for (const [id, session] of sessions) {
    if (Date.now() - session.touched > IDLE_MS) void closeSession(id);
  }
}, 30_000).unref();

async function shot(page) {
  return (await page.screenshot({ fullPage: false })).toString('base64');
}

async function startRecording(start) {
  if (sessions.size >= MAX_SESSIONS) throw Object.assign(new Error('too many recordings are open'), { status: 429 });
  const context = await browser.newContext({ acceptDownloads: false, serviceWorkers: 'block', viewport: VIEWPORT });
  await context.route('**/*', (route) =>
    hostAllowed(route.request().url(), start.allowed) ? route.continue() : route.abort('blockedbyclient'));
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  const id = randomUUID();
  sessions.set(id, { context, page, focused: null, password: false, touched: Date.now() });
  try {
    await page.goto(start.url, { waitUntil: 'domcontentloaded' });
  } catch (e) {
    await closeSession(id);
    throw e;
  }
  return { session: id, step: { kind: 'goto', url: start.url }, png_base64: await shot(page) };
}

async function recordAction(session, action, body) {
  session.touched = Date.now();
  const { page } = session;
  switch (action) {
    case 'click': {
      if (!pointOk(body)) throw Object.assign(new Error('x and y are inside the 1280 x 800 view'), { status: 422 });
      const info = await page.evaluate(ELEMENT_INFO, { x: body.x, y: body.y });
      const selector = selectorFor(info);
      await page.mouse.click(body.x, body.y);
      await page.waitForLoadState('domcontentloaded').catch(() => {});
      session.focused = selector;
      session.password = Boolean(info?.password);
      return { step: { kind: 'click', selector }, password: session.password, png_base64: await shot(page) };
    }
    case 'type': {
      if (!session.focused) throw Object.assign(new Error('click a field first'), { status: 422 });
      const text = String(body?.text ?? '');
      await page.fill(session.focused, text);
      const value = session.password ? '{{secret:password}}' : text;
      return { step: { kind: 'fill', selector: session.focused, value }, png_base64: await shot(page) };
    }
    case 'press': {
      if (!session.focused) throw Object.assign(new Error('click a field first'), { status: 422 });
      const key = String(body?.key ?? 'Enter');
      await page.press(session.focused, key);
      await page.waitForLoadState('domcontentloaded').catch(() => {});
      return { step: { kind: 'press', selector: session.focused, key }, png_base64: await shot(page) };
    }
    default:
      throw Object.assign(new Error('not_found'), { status: 404 });
  }
}

createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') return send(res, 200, { ok: browser.isConnected() });
    if (!authorised(req)) return send(res, 401, { error: 'unauthorised' });
    if (req.method === 'POST' && req.url === '/run') {
      const checked = checkRun(await readJson(req));
      if (!checked.ok) return send(res, 422, { error: checked.error });
      return send(res, 200, await runSteps(checked.run));
    }
    if (req.method === 'POST' && req.url === '/record') {
      const checked = checkStart(await readJson(req), hostAllowed);
      if (!checked.ok) return send(res, 422, { error: checked.error });
      return send(res, 200, await startRecording(checked.start));
    }
    const match = /^\/record\/([0-9a-f-]{36})(?:\/(click|type|press))?$/.exec(req.url ?? '');
    const session = match && sessions.get(match[1]);
    if (!session) return send(res, 404, { error: 'not_found' });
    if (req.method === 'DELETE' && !match[2]) {
      await closeSession(match[1]);
      res.writeHead(204).end();
      return;
    }
    if (req.method === 'POST' && match[2]) {
      return send(res, 200, await recordAction(session, match[2], await readJson(req)));
    }
    return send(res, 404, { error: 'not_found' });
  } catch (e) {
    return send(res, e?.status ?? 400, { error: String(e?.message ?? e).slice(0, 200) });
  }
}).listen(PORT, () => console.log(`rpa-browser listening on ${PORT}`));
