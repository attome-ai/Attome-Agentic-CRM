// U1-T2: the winget manifests. Run with `node --test packaging/winget/generate.test.mjs`.
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { PACKAGE_ID, manifests, normaliseVersion } from './generate.mjs';

const SHA = 'a'.repeat(64);
const URL = 'https://github.com/attome-ai/Attome-Agentic-CRM/releases/download/v1.2.3/attome-windows-x86_64.msi';

test('versions lose their v and must be three numbers', () => {
  assert.equal(normaliseVersion('v1.2.3'), '1.2.3');
  assert.throws(() => normaliseVersion('1.2'), /not a release version/);
  assert.throws(() => normaliseVersion('v1.2.3-rc1'), /not a release version/);
});

test('three manifests with the version, address and hash', () => {
  const files = manifests('v1.2.3', URL, SHA);
  assert.deepEqual(Object.keys(files).sort(), [
    `${PACKAGE_ID}.installer.yaml`, `${PACKAGE_ID}.locale.en-US.yaml`, `${PACKAGE_ID}.yaml`,
  ]);
  const installer = files[`${PACKAGE_ID}.installer.yaml`];
  assert.match(installer, /PackageVersion: 1\.2\.3\n/);
  assert.match(installer, /InstallerType: wix\n/);
  assert.match(installer, new RegExp(`InstallerUrl: ${URL.replace(/[.]/g, '\\.')}\n`));
  assert.match(installer, new RegExp(`InstallerSha256: ${'A'.repeat(64)}\n`));
  for (const text of Object.values(files)) assert.match(text, /ManifestVersion: 1\.6\.0\n/);
});

test('a bad address or hash is refused', () => {
  assert.throws(() => manifests('1.2.3', 'http://x/a.msi', SHA), /https/);
  assert.throws(() => manifests('1.2.3', URL, 'abc'), /64 hex/);
});
