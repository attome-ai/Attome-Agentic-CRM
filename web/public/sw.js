/*
 * B19-T2: the service worker the app registers. It adds one thing to
 * Angular's (ngsw-worker.js, imported below): the share target. When another
 * app shares files into Attome, the browser POSTs them here
 * (manifest.webmanifest `share_target`); they are kept in the Cache Storage
 * `attome-share` and the browser is sent to /xrm/share, which saves them as
 * the person's own documents through the API.
 *
 * This listener is registered before ngsw-worker.js, whose fetch listener
 * answers every request (POST included): once this one answers the share
 * POST it stops the event, so Angular's never sees it.
 */
const SHARE_PATH = '/share-target';
const SHARE_CACHE = 'attome-share';
/** Files kept from one share, at most. */
const MAX_FILES = 10;

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'POST' || url.pathname !== SHARE_PATH) return;
  event.respondWith(keepShare(event.request));
  event.stopImmediatePropagation();
});

async function keepShare(request) {
  const form = await request.formData();
  const cache = await caches.open(SHARE_CACHE);
  for (const key of await cache.keys()) await cache.delete(key);
  const files = form.getAll('files').filter(f => f instanceof File).slice(0, MAX_FILES);
  const names = [];
  for (const [i, file] of files.entries()) {
    names.push({ name: file.name, type: file.type });
    await cache.put(`${SHARE_PATH}/file/${i}`, new Response(file, { headers: { 'content-type': file.type || 'application/octet-stream' } }));
  }
  const meta = {
    title: String(form.get('title') ?? ''),
    text: String(form.get('text') ?? ''),
    url: String(form.get('url') ?? ''),
    files: names,
  };
  await cache.put(`${SHARE_PATH}/meta`, new Response(JSON.stringify(meta), { headers: { 'content-type': 'application/json' } }));
  return Response.redirect('/xrm/share', 303);
}

importScripts('./ngsw-worker.js');
