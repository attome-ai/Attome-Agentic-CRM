#!/usr/bin/env node
// C5-T2: writes the Teams app package's files into dist/: manifest.json, the
// Arabic localization ar.json and the two icons. Zip the four files (no
// folder inside the zip) and upload the zip in the Teams admin center.
//
//   node build.mjs --url https://crm.example.com --bot-app-id <id> --company "Example Co"
//     [--teams-app-id <uuid>]   (a new one is made when not given; keep it for updates)
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { deflateSync } from 'node:zlib';

const HERE = dirname(fileURLToPath(import.meta.url));
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The flags as an object. */
export function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!argv[i].startsWith('--')) throw new Error(`unexpected ${argv[i]}`);
    out[argv[i].slice(2)] = argv[i + 1];
  }
  return out;
}

/** The checked values the templates take. */
export function values(args) {
  const url = new URL(args.url ?? '');
  if (url.protocol !== 'https:') throw new Error('--url must be https');
  const bot = args['bot-app-id'] ?? '';
  if (!GUID.test(bot)) throw new Error('--bot-app-id is the Azure bot registration\'s app id (a GUID)');
  const app = args['teams-app-id'] ?? randomUUID();
  if (!GUID.test(app)) throw new Error('--teams-app-id is a GUID');
  const company = (args.company ?? '').trim();
  if (!company) throw new Error('--company names the publisher shown in Teams');
  return { URL: url.origin, HOST: url.host, BOT_APP_ID: bot, TEAMS_APP_ID: app, COMPANY: company };
}

/** `template` with every `{{NAME}}` filled, JSON-escaped. */
export function fill(template, vals) {
  return template.replace(/\{\{([A-Z_]+)\}\}/g, (_, name) => {
    if (!(name in vals)) throw new Error(`no value for ${name}`);
    return JSON.stringify(vals[name]).slice(1, -1);
  });
}

function crc32(bytes) {
  let c = ~0;
  for (const b of bytes) {
    c ^= b;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

function chunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, 'ascii'), data])), 8 + data.length);
  return out;
}

/** A square RGBA PNG of `size` pixels where `pixel(x, y)` gives [r, g, b, a]. */
export function png(size, pixel) {
  const rows = [];
  for (let y = 0; y < size; y++) {
    const row = Buffer.alloc(1 + size * 4);
    for (let x = 0; x < size; x++) Buffer.from(pixel(x, y)).copy(row, 1 + x * 4);
    rows.push(row);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', header),
    chunk('IDAT', deflateSync(Buffer.concat(rows))),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/** Teams' two icons: a 192 px colour one and a 32 px white-on-transparent outline. */
export function icons() {
  const ring = (size, x, y) => {
    const d = Math.hypot(x - size / 2 + 0.5, y - size / 2 + 0.5);
    return d < size * 0.42 && d > size * 0.26;
  };
  return {
    color: png(192, (x, y) => (ring(192, x, y) ? [255, 255, 255, 255] : [31, 78, 121, 255])),
    outline: png(32, (x, y) => (ring(32, x, y) ? [255, 255, 255, 255] : [0, 0, 0, 0])),
  };
}

function main() {
  const vals = values(parseArgs(process.argv.slice(2)));
  const dist = join(HERE, 'dist');
  mkdirSync(dist, { recursive: true });
  const manifest = fill(readFileSync(join(HERE, 'manifest.template.json'), 'utf8'), vals);
  JSON.parse(manifest);
  writeFileSync(join(dist, 'manifest.json'), manifest);
  writeFileSync(join(dist, 'ar.json'), readFileSync(join(HERE, 'ar.template.json'), 'utf8'));
  const { color, outline } = icons();
  writeFileSync(join(dist, 'color.png'), color);
  writeFileSync(join(dist, 'outline.png'), outline);
  console.log(`dist/ written for ${vals.HOST}; Teams app id ${vals.TEAMS_APP_ID}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
