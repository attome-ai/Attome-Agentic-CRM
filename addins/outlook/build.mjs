// C7-T1: writes dist/ for the Outlook add-in, served by the deployment (or any
// HTTPS host) at <url>/addins/outlook/:
//   node build.mjs --url https://crm.example.com
// dist/manifest.xml is what an administrator uploads to Microsoft 365
// ("Integrated apps") or a person sideloads in Outlook.
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const at = process.argv.indexOf('--url');
const given = at > 0 ? process.argv[at + 1] : '';
const url = (given || '').trim().replace(/\/+$/, '');
if (!/^https:\/\/[^\s/]+(\/[^\s]*)?$/i.test(url)) {
  console.error('usage: node build.mjs --url https://<your deployment>');
  process.exit(2);
}
const base = `${url}/addins/outlook/`;
const origin = new URL(url).origin;
const out = join(here, 'dist');
mkdirSync(out, { recursive: true });
const manifest = readFileSync(join(here, 'manifest.template.xml'), 'utf8')
  .replaceAll('{{BASE}}', base)
  .replaceAll('{{ORIGIN}}', origin);
writeFileSync(join(out, 'manifest.xml'), manifest);
for (const file of ['taskpane.html', 'taskpane.css', 'taskpane.js']) copyFileSync(join(here, file), join(out, file));
copyFileSync(join(here, '..', 'shared', 'attome-mail-client.js'), join(out, 'attome-mail-client.js'));
// The product icon the web app installs with.
copyFileSync(join(here, '..', '..', 'web', 'public', 'icons', 'icon-192.png'), join(out, 'icon.png'));
console.log(`wrote ${out}: serve it at ${base} and upload manifest.xml`);
