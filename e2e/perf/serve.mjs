// AA14-T6: serves the production build for the Core Web Vitals check, gzipped
// as the deployment's edge serves it, with the app's routes falling back to
// index.html. Build it first: `npm --prefix ../web run build`.
import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createGzip } from 'node:zlib';

const ROOT = resolve(fileURLToPath(new URL('.', import.meta.url)), '../../web/dist/attome-website/browser');
const PORT = 4198;
const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.svg': 'image/svg+xml',
  '.wasm': 'application/wasm',
  '.woff2': 'font/woff2',
  '.png': 'image/png',
};
const COMPRESSED = new Set(['.html', '.js', '.css', '.json', '.svg', '.wasm']);

createServer((request, response) => {
  const path = normalize(decodeURIComponent(new URL(request.url, 'http://localhost').pathname));
  let file = join(ROOT, path);
  if (!file.startsWith(ROOT) || !existsSync(file) || statSync(file).isDirectory()) {
    file = join(ROOT, 'index.html');
  }
  const type = extname(file);
  const headers = { 'content-type': TYPES[type] ?? 'application/octet-stream' };
  if (COMPRESSED.has(type)) {
    response.writeHead(200, { ...headers, 'content-encoding': 'gzip' });
    createReadStream(file).pipe(createGzip()).pipe(response);
  } else {
    response.writeHead(200, headers);
    createReadStream(file).pipe(response);
  }
}).listen(PORT);
