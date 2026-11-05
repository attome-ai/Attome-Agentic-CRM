//! T3-T4: `attome new component <tag>` — a TypeScript project for one custom
//! web component written against `@attome/component-sdk` (T3-T1): the
//! element, its manifest (`component.json`, the T3-T3 component kind), a
//! test and a README.
//!
//! The element reads its bound record through `attome.records` (as the
//! person viewing the page), shows its name in its shadow root with text
//! only, never HTML, and tells the page with `attome.events.emit`. The host
//! page sets `attome` and the bound properties (T3-T2's component host).
//!
//! `[--dir <folder>]` (default: the tag) must be new or empty;
//! `[--package <name>]` is the package the built module is published in, a
//! reverse-DNS id (default `local.<tag without hyphens>`, which `attome dev`
//! loads as is), so the manifest's module is `<package>/<tag>.js`.

#![allow(
    clippy::print_stdout,
    reason = "a command-line command reports to standard output"
)]

use std::path::PathBuf;

use serde_json::json;

use crate::cmd::output::take_value;

const USAGE: &str = "usage: attome new component <tag> [--dir <folder>] [--package <name>]";

/// The class name of a tag: `acme-credit-gauge` -> `AcmeCreditGauge`. Pure.
pub fn class_name(tag: &str) -> String {
    tag.split('-')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .map(|first| first.to_ascii_uppercase().to_string() + chars.as_str())
                .unwrap_or_default()
        })
        .collect()
}

/// The project's files, `(path, contents)`. Pure.
pub fn component_project(tag: &str, package: &str) -> Result<Vec<(String, String)>, String> {
    if !attome_model::kinds::component::valid_tag(tag) {
        return Err(format!(
            "{tag} is not a custom element name: lower case, starting with a letter, with a hyphen"
        ));
    }
    let module = format!("{package}/{tag}.js");
    if !attome_model::kinds::component::valid_module(&module) {
        return Err(format!("{package} is not a package name"));
    }
    let class = class_name(tag);
    let manifest = json!({
        "tag": tag,
        "module": module,
        "label_en": class,
        "label_ar": class,
        "properties": [
            { "name": "recordId", "type": "record_id", "bind": "record_id" },
            { "name": "entity", "type": "text", "bind": "entity_name" }
        ],
        "events": [ { "name": "opened", "payload": "record_id" } ]
    });
    let package_json = json!({
        "name": package,
        "private": true,
        "type": "module",
        "scripts": { "build": "tsc -p .", "test": "vitest run" },
        "dependencies": { "@attome/component-sdk": "1.0.0" },
        "devDependencies": { "jsdom": "26.1.0", "typescript": "5.8.3", "vitest": "3.2.4" }
    });
    let tsconfig = json!({
        "compilerOptions": {
            "target": "ES2022",
            "module": "ES2022",
            "moduleResolution": "bundler",
            "lib": ["ES2022", "DOM"],
            "strict": true,
            "declaration": false,
            "outDir": "dist",
            "rootDir": "src",
            "skipLibCheck": true
        },
        "include": ["src"],
        "exclude": ["src/**/*.test.ts"]
    });
    let pretty = |v: &serde_json::Value| serde_json::to_string_pretty(v).unwrap_or_default() + "\n";
    let element = format!(
        r#"import type {{ Attome }} from '@attome/component-sdk';

/**
 * <{tag}>: shows the bound record's name and tells the page it was opened.
 * The host page sets `attome`, `recordId` and `entity` (component.json).
 * Text only, never HTML: a record's values are data.
 */
export class {class} extends HTMLElement {{
  attome?: Attome;
  recordId = '';
  entity = '';
  private readonly root = this.attachShadow({{ mode: 'open' }});

  connectedCallback(): void {{
    void this.render();
  }}

  async render(): Promise<void> {{
    const text = document.createElement('p');
    this.root.replaceChildren(text);
    if (!this.attome || !this.recordId || !this.entity) {{
      text.textContent = '…';
      return;
    }}
    try {{
      const record = await this.attome.records.get(this.entity, this.recordId);
      text.textContent = String(record['name'] ?? record.id);
      text.style.color = this.attome.theme.tokens()['--color-primary'] ?? '';
      text.dir = this.attome.theme.dir();
      this.attome.events.emit('opened', record.id);
    }} catch (error) {{
      text.textContent = error instanceof Error ? error.message : String(error);
    }}
  }}
}}

if (!customElements.get('{tag}')) {{
  customElements.define('{tag}', {class});
}}
"#
    );
    let test = format!(
        r#"import {{ describe, expect, it, vi }} from 'vitest';
import type {{ Attome }} from '@attome/component-sdk';

import {{ {class} }} from './{tag}';

const ID = '0190a0b0-0000-7000-8000-000000000001';

function fakeAttome(): Attome {{
  return {{
    records: {{
      get: vi.fn(async () => ({{ id: ID, name: 'Acme' }})),
      list: vi.fn(),
      update: vi.fn(),
    }},
    events: {{ emit: vi.fn() }},
    theme: {{ tokens: () => ({{ '--color-primary': 'rgb(1, 2, 3)' }}), dir: () => 'ltr' as const }},
  }};
}}

describe('<{tag}>', () => {{
  it('shows the record name and tells the page', async () => {{
    const attome = fakeAttome();
    const element = document.createElement('{tag}') as {class};
    element.attome = attome;
    element.entity = 'account';
    element.recordId = ID;
    document.body.append(element);
    await element.render();
    expect(element.shadowRoot?.textContent).toBe('Acme');
    expect(attome.records.get).toHaveBeenCalledWith('account', ID);
    expect(attome.events.emit).toHaveBeenCalledWith('opened', ID);
  }});

  it('shows a value as text, never as HTML', async () => {{
    const attome = fakeAttome();
    vi.mocked(attome.records.get).mockResolvedValue({{ id: ID, name: '<img src=x onerror=alert(1)>' }});
    const element = document.createElement('{tag}') as {class};
    Object.assign(element, {{ attome, entity: 'account', recordId: ID }});
    await element.render();
    expect(element.shadowRoot?.querySelector('img')).toBeNull();
  }});
}});
"#
    );
    let vitest_config = "import { defineConfig } from 'vitest/config';\n\nexport default defineConfig({ test: { environment: 'jsdom' } });\n".to_owned();
    let readme = format!(
        "# {class}\n\n\
         A custom web component for Attome pages, written against `@attome/component-sdk`.\n\n\
         - `src/{tag}.ts`: the element. It reads its record as the person viewing the page.\n\
         - `component.json`: its manifest (tag, module, properties and their bindings, events),\n  \
         checked when it is published.\n\
         - `npm test` runs the test; `npm run build` writes `dist/{tag}.js`, the module the manifest\n  \
         names as `{module}` once it is published in the package `{package}`.\n\
         - `attome dev .` rebuilds on every change and loads each build into your target (or the\n  \
         workspace `attome workspace switch` chose), signed with a development key the target must\n  \
         trust (`.attome/dev.key`; keep `.attome/` out of version control).\n"
    );
    Ok(vec![
        ("package.json".into(), pretty(&package_json)),
        ("tsconfig.json".into(), pretty(&tsconfig)),
        ("vitest.config.ts".into(), vitest_config),
        ("component.json".into(), pretty(&manifest)),
        (format!("src/{tag}.ts"), element),
        (format!("src/{tag}.test.ts"), test),
        ("README.md".into(), readme),
    ])
}

pub fn run(args: &[String]) -> Result<(), String> {
    let mut args = args.to_vec();
    let dir = take_value(&mut args, "--dir")?;
    let package = take_value(&mut args, "--package")?;
    let [kind, tag] = args.as_slice() else {
        return Err(USAGE.to_owned());
    };
    if kind != "component" {
        return Err(USAGE.to_owned());
    }
    let default_package = format!("local.{}", tag.replace('-', ""));
    let files = component_project(tag, package.as_deref().unwrap_or(&default_package))?;
    let dir = PathBuf::from(dir.unwrap_or_else(|| tag.clone()));
    if std::fs::read_dir(&dir).is_ok_and(|mut entries| entries.next().is_some()) {
        return Err(format!("{} exists and is not empty", dir.display()));
    }
    for (path, contents) in &files {
        let path = dir.join(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
        std::fs::write(&path, contents).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    println!(
        "created {} ({} files); run `npm install` and `npm test` there",
        dir.display(),
        files.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_component_generates_a_project_with_a_valid_manifest() {
        let files = component_project("acme-credit-gauge", "acme-credit").unwrap();
        let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "package.json",
                "tsconfig.json",
                "vitest.config.ts",
                "component.json",
                "src/acme-credit-gauge.ts",
                "src/acme-credit-gauge.test.ts",
                "README.md",
            ]
        );
        let manifest: serde_json::Value = serde_json::from_str(&files[3].1).unwrap();
        assert_eq!(manifest["module"], "acme-credit/acme-credit-gauge.js");
        let element = &files[4].1;
        assert!(element.contains("export class AcmeCreditGauge extends HTMLElement {"));
        assert!(element.contains("customElements.define('acme-credit-gauge', AcmeCreditGauge);"));
        assert!(!element.contains("innerHTML"), "text only");
        assert!(
            files[5]
                .1
                .contains("import { AcmeCreditGauge } from './acme-credit-gauge';")
        );
    }

    #[test]
    fn new_component_refuses_a_bad_tag() {
        assert!(component_project("Gauge", "p").is_err());
        assert!(
            component_project("gauge", "p").is_err(),
            "a tag needs a hyphen"
        );
        assert!(
            component_project("font-face", "p").is_err(),
            "HTML reserves it"
        );
        assert_eq!(class_name("x-y-zed"), "XYZed");
    }
}
