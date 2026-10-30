// C7-T1: writes dist/ for the Gmail add-on, an Apps Script project for one
// deployment:
//   node build.mjs --url https://crm.example.com
// then push dist/ with `clasp push` and deploy it in the Google Workspace
// admin console (or test it from the Apps Script editor).
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const at = process.argv.indexOf('--url');
const url = (at > 0 ? process.argv[at + 1] : '').trim().replace(/\/+$/, '');
if (!/^https:\/\/[^\s/]+(\/[^\s]*)?$/i.test(url)) {
  console.error('usage: node build.mjs --url https://<your deployment>');
  process.exit(2);
}
const out = join(here, 'dist');
mkdirSync(out, { recursive: true });
writeFileSync(
  join(out, 'appsscript.json'),
  readFileSync(join(here, 'appsscript.template.json'), 'utf8').replaceAll('{{BASE}}', `${url}/`),
);
copyFileSync(join(here, 'Code.js'), join(out, 'Code.js'));
// Apps Script loads files in order; the shared client must come first.
copyFileSync(join(here, '..', 'shared', 'attome-mail-client.js'), join(out, 'AttomeMail.js'));
writeFileSync(join(out, '.claspignore'), '');
console.log(`wrote ${out}: clasp push it, with AttomeMail.js before Code.js`);
