// @ts-check
const eslint = require("@eslint/js");
const { defineConfig } = require("eslint/config");
const tseslint = require("typescript-eslint");
const angular = require("angular-eslint");

module.exports = defineConfig([
  {
    ignores: ["**/generated/**"],
  },
  {
    files: ["**/*.ts"],
    extends: [
      eslint.configs.recommended,
      tseslint.configs.recommended,
      tseslint.configs.stylistic,
      angular.configs.tsRecommended,
    ],
    processor: angular.processInlineTemplates,
    rules: {
      // Leading underscore = intentionally unused, an existing repo convention
      // (override-hook params, rest-destructure omission) predating this lint baseline.
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          destructuredArrayIgnorePattern: "^_",
          ignoreRestSiblings: true,
        },
      ],
      "@typescript-eslint/no-empty-function": ["error", { allow: ["methods"] }],
      "@angular-eslint/no-input-rename": "error",
      // Angular v22 makes OnPush the *default*: a component that omits
      // `changeDetection` is OnPush, and the only way to lose it is to opt out
      // explicitly with `ChangeDetectionStrategy.Eager` (or the deprecated
      // `Default`, which is the same value). This rule reports exactly that
      // opt-out, which is what D-307's "every component is OnPush" needs in
      // order to stay true — the explicit annotations it added cannot be
      // enforced by lint, because omitting them is equally correct.
      // Deliberately not scoped away from *.spec.ts: a test host on `Eager`
      // would mask an OnPush defect in the component under test.
      "@angular-eslint/prefer-on-push-component-change-detection": "error",
    },
  },
  // Selector prefix is scoped per project rather than one rule allowing all
  // three prefixes everywhere (P-ci-green §4(c)) — a shared allow-list would
  // let an "xrm-" component sneak into the host app, or an "app-" one into a
  // library, without lint ever catching it. Each project keeps its own
  // already-established convention: host app -> "app" (CLI default),
  // @attome/base -> "base", @attome/xrm -> "xrm".
  {
    files: ["src/app/**/*.ts"],
    rules: {
      "@angular-eslint/directive-selector": [
        "error",
        { type: "attribute", prefix: "app", style: "camelCase" },
      ],
      "@angular-eslint/component-selector": [
        "error",
        { type: "element", prefix: "app", style: "kebab-case" },
      ],
    },
  },
  {
    files: ["projects/base/**/*.ts"],
    rules: {
      "@angular-eslint/directive-selector": [
        "error",
        { type: "attribute", prefix: "base", style: "camelCase" },
      ],
      "@angular-eslint/component-selector": [
        "error",
        { type: "element", prefix: "base", style: "kebab-case" },
      ],
    },
  },
  {
    files: ["projects/xrm/**/*.ts"],
    rules: {
      "@angular-eslint/directive-selector": [
        "error",
        { type: "attribute", prefix: "xrm", style: "camelCase" },
      ],
      // D-314: an ng-packagr entry point compiles to one flat FESM module, so
      // importing a sibling's component barrel to reach a *service* drags that
      // sibling's components into the chunk. That is how the entity wildcard
      // route — the hottest route in the product — came to ship the query,
      // admin and license admin screens in one 448.64 kB chunk. These two
      // barrels have services-only `*/data` siblings; reach for those instead.
      // The host app (`src/**`) is deliberately not covered: its lazy routes
      // import these barrels for `loadComponent()`, which is the whole point.
      //
      // The `name`s MUST be the entry points' CURRENT import specifiers: this
      // rule matches the literal string, so when `query` and `admin` moved
      // under `projects/xrm/core/` (specifiers `@attome/xrm/core/query` and
      // `@attome/xrm/core/admin`) the old `@attome/xrm/query`/`/admin` entries
      // matched nothing and the rule was silently dead for the whole window.
      // Verify with `npm run lint:xrm` on a deliberate violation, never with a
      // bare `npx eslint` (see D-314's probe note). The specifiers below map
      // 1:1 onto `projects/xrm/**/ng-package.json` directories.
      "no-restricted-imports": [
        "error",
        {
          paths: [
            { name: "@attome/xrm/core/query", message: "Import services/types from '@attome/xrm/core/query/data' (D-314) — this barrel pulls the query and view editor components." },
            { name: "@attome/xrm/core/admin", message: "Import services/types from '@attome/xrm/core/admin/data' (D-314) — this barrel pulls the entity manager, entity editor, sidebar manager and system settings components." },
          ],
        },
      ],
      "@angular-eslint/component-selector": [
        "error",
        { type: "element", prefix: "xrm", style: "kebab-case" },
      ],
    },
  },
  {
    files: ["**/*.html"],
    extends: [
      angular.configs.templateRecommended,
      angular.configs.templateAccessibility,
    ],
    rules: {
      "@angular-eslint/template/click-events-have-key-events": "error",
      "@angular-eslint/template/interactive-supports-focus": "error",
      "@angular-eslint/template/label-has-associated-control": "error",
    },
  }
]);
