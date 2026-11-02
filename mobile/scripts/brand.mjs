// B17-T11: a branded build of the phone app.
//
//   npm run brand -- <brand>
//
// reads mobile/brands/<brand>.json, copies the shell to mobile/build/<brand>/
// (node_modules and earlier builds left out), and stamps the brand on it:
// capacitor.config.ts gets the brand's appId and appName; www/brand.json
// carries the deployment address, which makes the connect page go straight
// there, and the push mode; the icon and splash are copied to assets/ and
// @capacitor/assets turns them into every Android size; the Arabic app name
// is written to Android's values-ar strings. The native project must exist
// (npx cap add android, once, in mobile/) for the Android steps.

import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Every problem with a brand file, at once. */
export function checkBrand(brand) {
  const problems = [];
  if (!/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){2,}$/.test(brand.appId ?? "")) {
    problems.push("appId is a reverse-domain id such as io.attome.acme");
  }
  if (!brand.appName) problems.push("appName is required");
  if (!brand.appNameAr) problems.push("appNameAr is required");
  for (const key of ["iconPng", "splashPng"]) {
    if (!brand[key] || !brand[key].endsWith(".png")) problems.push(`${key} is a .png file`);
  }
  if (!/^#[0-9a-fA-F]{6}$/.test(brand.primaryColor ?? "")) {
    problems.push("primaryColor is #rrggbb");
  }
  if (brand.deploymentUrl !== undefined && !/^https:\/\/[^\s/]+/.test(brand.deploymentUrl)) {
    problems.push("deploymentUrl, when set, is an https:// address");
  }
  if (!["relay", "own_keys"].includes(brand.pushMode)) {
    problems.push("pushMode is relay or own_keys");
  }
  return problems;
}

/** capacitor.config.ts with the brand's id and name. */
export function stampConfig(text, brand) {
  return text
    .replace(/appId: '[^']*'/, `appId: '${brand.appId}'`)
    .replace(/appName: '[^']*'/, `appName: '${brand.appName.replace(/'/g, "\\'")}'`);
}

/** Android's Arabic strings file. */
export function arabicStrings(brand) {
  const escape = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/'/g, "\\'");
  return `<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">${escape(brand.appNameAr)}</string>
    <string name="title_activity_main">${escape(brand.appNameAr)}</string>
</resources>
`;
}

function main(name) {
  if (!name || !/^[a-z0-9-]+$/.test(name)) {
    console.error("usage: npm run brand -- <brand>   (mobile/brands/<brand>.json)");
    process.exit(1);
  }
  const file = join(root, "brands", `${name}.json`);
  const brand = JSON.parse(readFileSync(file, "utf8"));
  const problems = checkBrand(brand);
  if (problems.length > 0) {
    console.error(`${file}:\n  ${problems.join("\n  ")}`);
    process.exit(1);
  }
  const out = join(root, "build", name);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync(root, out, {
    recursive: true,
    filter: (src) => {
      const rel = src.slice(root.length).replace(/\\/g, "/");
      return !rel.startsWith("/node_modules") && !rel.startsWith("/build");
    },
  });

  const config = join(out, "capacitor.config.ts");
  writeFileSync(config, stampConfig(readFileSync(config, "utf8"), brand));
  const www = {
    deploymentUrl: brand.deploymentUrl ?? null,
    pushMode: brand.pushMode,
    primaryColor: brand.primaryColor,
  };
  writeFileSync(join(out, "www", "brand.json"), `${JSON.stringify(www, null, 2)}\n`);

  const assets = join(out, "assets");
  mkdirSync(assets, { recursive: true });
  const from = (p) => resolve(dirname(file), p);
  cpSync(from(brand.iconPng), join(assets, "icon-only.png"));
  cpSync(from(brand.splashPng), join(assets, "splash.png"));

  const android = join(out, "android");
  if (existsSync(android)) {
    const npx = process.platform === "win32" ? "npx.cmd" : "npx";
    execFileSync(
      npx,
      [
        "@capacitor/assets",
        "generate",
        "--android",
        "--iconBackgroundColor",
        brand.primaryColor,
        "--splashBackgroundColor",
        brand.primaryColor,
      ],
      { cwd: out, stdio: "inherit" },
    );
    const valuesAr = join(android, "app", "src", "main", "res", "values-ar");
    mkdirSync(valuesAr, { recursive: true });
    writeFileSync(join(valuesAr, "strings.xml"), arabicStrings(brand));
    console.log(`branded Android project: ${android}`);
  } else {
    console.log("no android/ yet: run `npx cap add android` in mobile/ first, then brand again");
  }
  console.log(`branded build: ${out}`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv[2]);
}
