// AA1-T3: agent traffic. Each VU opens an MCP session (`initialize`, whose
// response carries `Mcp-Session-Id`) and then sends JSON-RPC `tools/call`
// requests to POST /api/v1/mcp for the read tool (`record.get`) and the
// search tool (`search.records`), tagged `op: mcp`. The calls use the legacy
// envelope (no `_meta` protocol version), which needs no extra transport
// headers.
//
// The MCP surface needs a caller who may use agents; MCP_EMAIL /
// MCP_PASSWORD default to the admin from seed-info.json.
import http from 'k6/http';
import { check } from 'k6';
import { baseUrls, pickBaseUrl, login, jsonHeaders } from './lib/http.js';

const BULK_ENTITY = __ENV.BULK_ENTITY || 'loadtest_bulk';
const BULK_QUERY_ID = __ENV.BULK_QUERY_ID;
const BULK_ROW_COUNT = Number(__ENV.BULK_ROW_COUNT || 100000);

export const options = {
  vus: Number(__ENV.VUS || 10),
  duration: __ENV.DURATION || '60s',
  summaryTrendStats: ['p(50)', 'p(95)', 'p(99)', 'max'],
  thresholds: { 'http_req_duration{op:mcp}': ['max>=0'] },
};

export function setup() {
  const baseUrl = baseUrls()[0];
  const cookie = login(
    baseUrl,
    __ENV.MCP_EMAIL || __ENV.ADMIN_EMAIL,
    __ENV.MCP_PASSWORD || __ENV.ADMIN_PASSWORD
  );
  const res = http.post(
    `${baseUrl}/api/v1/query/execute`,
    JSON.stringify({ query_id: BULK_QUERY_ID, page: 1, page_size: 100 }),
    { headers: jsonHeaders(cookie) }
  );
  if (res.status !== 200) {
    throw new Error(`setup: sampling record ids failed (${res.status}): ${res.body}`);
  }
  return { cookie, ids: JSON.parse(res.body).data.records.map((r) => r.id) };
}

let session = null;
let nextId = 1;

function rpc(baseUrl, cookie, method, params, extraHeaders = {}) {
  return http.post(
    `${baseUrl}/api/v1/mcp`,
    JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, params }),
    {
      headers: jsonHeaders(cookie, { Accept: 'application/json', ...extraHeaders }),
      tags: { name: `mcp_${method}`, op: method === 'tools/call' ? 'mcp' : 'mcp_setup' },
    }
  );
}

export default function (data) {
  const baseUrl = pickBaseUrl();
  if (session === null) {
    const init = rpc(baseUrl, data.cookie, 'initialize', {
      protocolVersion: '2025-06-18',
      capabilities: {},
      clientInfo: { name: 'attome-loadtest', version: '1' },
    });
    check(init, { 'initialize 200': (r) => r.status === 200 });
    session = init.headers['Mcp-Session-Id'] || init.headers['mcp-session-id'] || null;
    if (!session) {
      throw new Error(`initialize returned no Mcp-Session-Id (status ${init.status}): ${init.body}`);
    }
  }
  const headers = { 'Mcp-Session-Id': session };
  const res =
    __ITER % 2 === 0
      ? rpc(
          baseUrl,
          data.cookie,
          'tools/call',
          {
            name: 'record.get',
            arguments: {
              entity: BULK_ENTITY,
              record_id: data.ids[(__VU + __ITER) % data.ids.length],
            },
          },
          headers
        )
      : rpc(
          baseUrl,
          data.cookie,
          'tools/call',
          {
            name: 'search.records',
            arguments: { query: `bulk-row-${Math.floor(Math.random() * BULK_ROW_COUNT)}` },
          },
          headers
        );
  check(res, {
    'tools/call 200': (r) => r.status === 200,
    'tools/call has a result': (r) => {
      try {
        return JSON.parse(r.body).result !== undefined;
      } catch {
        return false;
      }
    },
  });
}
