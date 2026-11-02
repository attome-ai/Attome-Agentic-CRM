#!/usr/bin/env node
// U1-T2: the winget manifests for one release, generated from its version,
// the MSI's download address and its SHA-256. The release workflow writes
// them next to the MSI; submitting them to microsoft/winget-pkgs is a
// separate, reviewed step.
//
//   node packaging/winget/generate.mjs <version> <msi-url> <sha256> <out-dir>
//
// Writes Attome.Attome.yaml, Attome.Attome.installer.yaml and
// Attome.Attome.locale.en-US.yaml (manifest schema 1.6.0).

import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PACKAGE_ID = 'Attome.Attome';
export const MANIFEST_VERSION = '1.6.0';

/** A version winget and the MSI accept: three numbers, no `v`. */
export function normaliseVersion(raw) {
  const version = String(raw).trim().replace(/^v/, '');
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error(`not a release version: ${raw}`);
  return version;
}

/** The three manifests, as file name to YAML text. Pure. */
export function manifests(rawVersion, url, sha256) {
  const version = normaliseVersion(rawVersion);
  if (!/^https:\/\//.test(url)) throw new Error('the MSI address must be https');
  if (!/^[0-9a-fA-F]{64}$/.test(sha256)) throw new Error('the SHA-256 must be 64 hex characters');
  const head = (type) =>
    `# yaml-language-server: $schema=https://aka.ms/winget-manifest.${type}.${MANIFEST_VERSION}.schema.json\n` +
    `PackageIdentifier: ${PACKAGE_ID}\nPackageVersion: ${version}\n`;
  return {
    [`${PACKAGE_ID}.yaml`]:
      head('version') + `DefaultLocale: en-US\nManifestType: version\nManifestVersion: ${MANIFEST_VERSION}\n`,
    [`${PACKAGE_ID}.installer.yaml`]:
      head('installer') +
      'InstallerType: wix\nScope: machine\nInstallModes:\n  - interactive\n  - silent\n' +
      'Installers:\n' +
      '  - Architecture: x64\n' +
      `    InstallerUrl: ${url}\n` +
      `    InstallerSha256: ${sha256.toUpperCase()}\n` +
      `ManifestType: installer\nManifestVersion: ${MANIFEST_VERSION}\n`,
    [`${PACKAGE_ID}.locale.en-US.yaml`]:
      head('defaultLocale') +
      'PackageLocale: en-US\nPublisher: Attome\nPublisherUrl: https://attome.com\n' +
      'PackageName: Attome\nPackageUrl: https://github.com/attome-ai/Attome-Agentic-CRM\n' +
      'License: AGPL-3.0-only\n' +
      'ShortDescription: The agentic CRM platform, self-hosted from one binary.\n' +
      'Moniker: attome\nTags:\n  - crm\n  - self-hosted\n' +
      `ManifestType: defaultLocale\nManifestVersion: ${MANIFEST_VERSION}\n`,
  };
}

function main(argv) {
  const [version, url, sha256, outDir] = argv.slice(2);
  if (!version || !url || !sha256 || !outDir) {
    console.error('usage: node packaging/winget/generate.mjs <version> <msi-url> <sha256> <out-dir>');
    process.exit(2);
  }
  mkdirSync(outDir, { recursive: true });
  for (const [name, text] of Object.entries(manifests(version, url, sha256))) {
    writeFileSync(join(outDir, name), text);
  }
  console.log(`winget manifests for ${normaliseVersion(version)} in ${outDir}`);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main(process.argv);
}
