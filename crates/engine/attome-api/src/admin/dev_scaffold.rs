//! Dev-only Angular component scaffolding, triggered from Entity
//! Management's "Add Form" / "Add List" buttons.
//!
//! Not a production capability: writes source files into the local Angular
//! checkout so a developer can review/build/commit a starting-point override,
//! the same role `ng generate component` plays elsewhere. This module does not
//! exist at all in a release build (`#[cfg(debug_assertions)]` on the `mod`
//! declaration in `admin/mod.rs`), and even in a debug build it refuses to run
//! without both `APP_ENV=debug` and `ATTOME_DEV_SCAFFOLD=1` — a double gate
//! (`server/src/dev_access_seed.rs` follows the same convention).
//! `CARGO_MANIFEST_DIR` anchors the write to whatever checkout built the
//! running binary, which is only ever meaningful for a `cargo run` against
//! this monorepo — a deployed binary has no such tree beside it, so the write
//! is a no-op failure there even if the gates above were somehow bypassed.
//!
//! # Caller-supplied target directory
//!
//! The caller names the destination directory (`target_dir`), because where a
//! component belongs is a judgement call this tool can't make — `forms/user/`,
//! `forms/invoice/`, a vertical's own folder. That makes the request body a
//! filesystem path from an HTTP client, so [`resolve_target_dir`] is the load-
//! bearing part of this module: the path must be absolute, must contain no
//! `..` component, and must resolve inside this checkout's `angular/`
//! directory. Everything else here is string templating.

use attome_core::EngineState;
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::AppError;
use attome_types::ErrorResponse;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::path::{Component, PathBuf};
use utoipa::ToSchema;
use uuid::Uuid;

const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn dev_gate_open() -> bool {
    attome_config::is_debug_env() && std::env::var("ATTOME_DEV_SCAFFOLD").as_deref() == Ok("1")
}

/// `crates/engine/attome-api` -> repo root is three levels up; the Angular workspace is `web/`.
fn angular_root() -> PathBuf {
    PathBuf::from(MANIFEST_DIR).join("../../../web")
}

/// Directory holding `provide-xrm-forms.ts`, `xrm-form.base.ts`, and
/// `xrm-form.css` — every generated form component imports from here, and the
/// registry this appends to lives here.
fn form_dir() -> PathBuf {
    angular_root().join("projects/xrm/forms/xrm-form")
}

/// Which of the two entity pages to generate. `EntityRouteRegistry` keys both
/// off the same logicalname (`{ formComponent, listComponent }`), so the two
/// kinds differ only in template, base class, and registry field.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub(super) enum ScaffoldKind {
    Form,
    List,
}

impl ScaffoldKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::Form => "form",
            Self::List => "list",
        }
    }

    /// The `EntityRouteOverride` field the generated class is registered under.
    fn registry_field(self) -> &'static str {
        match self {
            Self::Form => "formComponent",
            Self::List => "listComponent",
        }
    }

    fn class_suffix(self) -> &'static str {
        match self {
            Self::Form => "FormComponent",
            Self::List => "ListComponent",
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub(super) struct ScaffoldBody {
    kind: ScaffoldKind,
    /// Absolute path to the directory the three files are written into.
    /// Created if missing. Must resolve inside this checkout's `angular/`.
    target_dir: String,
}

#[derive(Serialize, ToSchema)]
pub(super) struct DevToolsAvailable {
    available: bool,
    /// Absolute path of this checkout's `angular/` directory, so the UI can
    /// pre-fill the path box with a directory that will actually pass
    /// `resolve_target_dir` instead of making the user guess it.
    angular_root: String,
    /// The conventional home for entity overrides — the only subtree from
    /// which `provide-xrm-forms.ts` can import with a library-safe relative
    /// path, and therefore the only one this tool auto-registers.
    suggested_dir: String,
}

/// `GET /api/v1/admin/dev-tools/available` — lets the Angular admin UI hide
/// the scaffold buttons entirely against anything other than a local dev
/// backend, rather than show buttons that then 403.
#[cfg(debug_assertions)]
/// Available developer tools
///
/// Available developer tools. Administrators only.
#[utoipa::path(
    get,
    path = "/api/v1/admin/dev-tools/available",
    tag = "admin",
    responses(
        (status = 200, description = "Success", body = DevToolsAvailable),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn dev_tools_available(
    _ctx: Authorized<Privilege<area::DataModel>>,
) -> Result<Json<DevToolsAvailable>, AppError> {
    let root = canonical_angular_root().unwrap_or_else(|_| angular_root());
    Ok(Json(DevToolsAvailable {
        available: dev_gate_open(),
        angular_root: display_path(&root),
        suggested_dir: display_path(&root.join("projects").join("xrm").join("forms")),
    }))
}

/// A canonical path as a human would type it.
///
/// `Path::canonicalize` on Windows returns an extended-length path
/// (`\\?\C:\…`). That form round-trips fine through `resolve_target_dir` — it
/// canonicalizes both sides before comparing, so a plain `C:\…` the user typed
/// and a `\\?\C:\…` it echoed back both resolve identically — but it is not
/// what anyone expects to see pre-filled in a text box, and pasting it into a
/// shell or editor is a nuisance. Stripped for *display only*; every
/// containment decision still runs on the canonical value.
fn display_path(path: &std::path::Path) -> String {
    let s = path.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned()
}

#[derive(Serialize, ToSchema)]
pub(super) struct ScaffoldResult {
    /// The `.ts`, `.html`, and `.css` files written, in that order.
    files: Vec<String>,
    registry_updated: bool,
    /// Why `registry_updated` is false, when it is — the caller has to know
    /// whether to go add the registration by hand.
    registry_note: Option<String>,
}

/// `user_account` -> `UserAccount`.
fn class_prefix(logicalname: &str) -> String {
    logicalname
        .split('_')
        .filter(|s| !s.is_empty())
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// Resolves the caller's `target_dir` to a real path inside this checkout's
/// `angular/` tree, or fails.
///
/// Three independent checks, because this is an HTTP-supplied filesystem path:
///
/// 1. **Absolute** — a relative path would resolve against the server process's
///    working directory, which the caller cannot see and did not intend.
/// 2. **No `..` component** — checked lexically, *before* any filesystem
///    access. This is what makes step 3 sound for a directory that does not
///    exist yet: with no `..` anywhere in the requested path, no suffix
///    appended to a contained ancestor can leave the containing tree.
/// 3. **Inside `angular/`** — compared against the *canonicalized* root, and
///    the target's own deepest existing ancestor is canonicalized too, so a
///    symlink or a `C:` vs `c:` spelling can't defeat the prefix test.
fn resolve_target_dir(requested: &str) -> Result<PathBuf, AppError> {
    let requested = requested.trim();
    if requested.is_empty() {
        return Err(AppError::Validation("target_dir is required".into()));
    }
    let target = PathBuf::from(requested);
    if !target.is_absolute() {
        return Err(AppError::Validation(format!(
            "target_dir must be an absolute path, got: {requested}"
        )));
    }
    if target.components().any(|c| c == Component::ParentDir) {
        return Err(AppError::Validation(
            "target_dir must not contain a '..' component".into(),
        ));
    }

    let root = canonical_angular_root()?;

    // Deepest ancestor that exists today — the tail below it is what we're
    // about to create. `..` is already ruled out, so the tail cannot escape.
    let mut existing = target.as_path();
    while !existing.exists() {
        existing = existing.parent().ok_or_else(|| {
            AppError::Validation(format!(
                "target_dir has no existing ancestor to create it under: {requested}"
            ))
        })?;
    }
    let existing_canonical = existing.canonicalize().map_err(|e| {
        AppError::Validation(format!(
            "target_dir could not be resolved: {requested} ({e})"
        ))
    })?;
    if !existing_canonical.starts_with(&root) {
        return Err(AppError::Validation(format!(
            "target_dir must be inside this checkout's angular/ directory ({}), got: {}",
            display_path(&root),
            requested
        )));
    }

    // Re-attach the not-yet-created tail to the canonical ancestor so callers
    // downstream compare canonical paths against canonical paths.
    let tail = target
        .strip_prefix(existing)
        .unwrap_or(std::path::Path::new(""));
    Ok(existing_canonical.join(tail))
}

fn canonical_angular_root() -> Result<PathBuf, AppError> {
    angular_root().canonicalize().map_err(|e| {
        AppError::internal(format!(
            "this backend has no angular/ checkout beside it, so nothing can be scaffolded: {e}"
        ))
    })
}

/// Relative module specifier from `from_dir` to `to_path`, in the `./x` /
/// `../x` form a TypeScript import needs. Both inputs must be canonical (or at
/// least share a canonical prefix) — `resolve_target_dir` and
/// `canonical_angular_root` guarantee that for every caller here.
fn relative_specifier(from_dir: &std::path::Path, to_path: &std::path::Path) -> String {
    let from: Vec<_> = from_dir.components().collect();
    let to: Vec<_> = to_path.components().collect();
    let shared = from
        .iter()
        .zip(to.iter())
        .take_while(|(a, b)| a == b)
        .count();

    let mut parts: Vec<String> = vec!["..".to_owned(); from.len() - shared];
    parts.extend(
        to[shared..]
            .iter()
            .map(|c| c.as_os_str().to_string_lossy().into_owned()),
    );
    let joined = parts.join("/");
    if joined.starts_with("..") {
        joined
    } else {
        format!("./{joined}")
    }
}

/// Scaffold an entity's screens
///
/// `POST /api/v1/admin/entities/{entity_id}/scaffold-ui` — writes a
/// three-file (`.ts` / `.html` / `.css`) starting-point form or list component
/// into the caller's chosen directory and, when that directory sits under
/// `projects/xrm/forms/`, appends its registration to `provide-xrm-forms.ts`.
/// The caller is expected to review the generated files, run the Angular
/// build, and commit them normally; this never attempts to make the component
/// live without a rebuild.
#[utoipa::path(
    post,
    path = "/api/v1/admin/entities/{entity_id}/scaffold-ui",
    tag = "admin",
    extensions(("x-audit-exempt" = json!(attome_audit::security::x_audit_exempt(
        attome_audit::security::ExemptReason::DevTooling,
        None,
        "dev-only Angular component scaffolder, gated off in production (dev_gate_open()); writes starting-point .ts/.html/.css files to the caller's local filesystem for the developer to review and commit, never touches customer data or metadata",
    )))),
    params(("entity_id" = Uuid, Path, description = "The entity")),
    request_body = ScaffoldBody,
    responses(
        (status = 201, description = "Success", body = ScaffoldResult),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
        (status = 422, description = "Request failed validation", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(super) async fn scaffold_form_component(
    State(state): State<EngineState>,
    ctx: Authorized<Privilege<area::DataModel>>,
    Path(entity_id): Path<Uuid>,
    Json(body): Json<ScaffoldBody>,
) -> Result<(StatusCode, Json<ScaffoldResult>), AppError> {
    if !dev_gate_open() {
        return Err(AppError::NotFound);
    }

    let logicalname: Option<String> =
        sqlx::query_scalar("SELECT logicalname FROM entity_info WHERE id = $1")
            .bind(entity_id)
            .fetch_optional(&state.base.db_migrator)
            .await
            .map_err(AppError::internal)?
            .flatten();

    let logicalname = logicalname.ok_or(AppError::NotFound)?;
    if !attome_metadata::provision::valid_identifier(&logicalname) {
        // Every entity created through create_entity() already satisfies
        // this; a legacy/pre-validation row failing it is not this
        // dev-only tool's problem to repair.
        return Err(AppError::Validation(
            "entity logicalname is not safe to scaffold a filename from".into(),
        ));
    }

    let target_dir = resolve_target_dir(&body.target_dir)?;
    let kind = body.kind;

    // Scaffold file layout only: every underscore becomes a '/' (a folder
    // path). This is not the app URL — non-`xrm_` names route as
    // `xrm/entity/{logicalname}` (Angular's logicalToUrlPath).
    let url_path = logicalname.replace('_', "/");
    let file_stem = format!("{}-{}", url_path.replace('/', "-"), kind.suffix());
    let class_name = format!("{}{}", class_prefix(&logicalname), kind.class_suffix());
    let selector = format!("xrm-{file_stem}");

    let ts_file = target_dir.join(format!("{file_stem}.component.ts"));
    let html_file = target_dir.join(format!("{file_stem}.component.html"));
    let css_file = target_dir.join(format!("{file_stem}.component.css"));

    // Checked before the first write so a half-scaffolded directory is never
    // left behind, and so an existing hand-edited component is never
    // silently overwritten.
    for f in [&ts_file, &html_file, &css_file] {
        if tokio::fs::try_exists(f).await.map_err(AppError::internal)? {
            return Err(AppError::Conflict(
                "a component file already exists at this path — delete it or choose another directory",
            ));
        }
    }

    tokio::fs::create_dir_all(&target_dir)
        .await
        .map_err(AppError::internal)?;

    let form_base_dir = form_dir()
        .canonicalize()
        .map_err(|e| AppError::internal(format!("xrm-form directory is missing: {e}")))?;
    let ts = match kind {
        ScaffoldKind::Form => form_component_ts(
            &logicalname,
            &url_path,
            &class_name,
            &selector,
            &file_stem,
            &relative_specifier(&target_dir, &form_base_dir),
        ),
        ScaffoldKind::List => {
            list_component_ts(&logicalname, &url_path, &class_name, &selector, &file_stem)
        }
    };
    let html = match kind {
        ScaffoldKind::Form => FORM_TEMPLATE_HTML.to_owned(),
        ScaffoldKind::List => LIST_TEMPLATE_HTML.to_owned(),
    };
    let css = component_css(&logicalname, kind);

    tokio::fs::write(&ts_file, ts)
        .await
        .map_err(AppError::internal)?;
    tokio::fs::write(&html_file, html)
        .await
        .map_err(AppError::internal)?;
    tokio::fs::write(&css_file, css)
        .await
        .map_err(AppError::internal)?;

    let (registry_updated, registry_note) =
        register_component(&target_dir, &file_stem, &class_name, &logicalname, kind)
            .await
            .map_err(AppError::internal)?;

    tracing::info!(
        entity = %logicalname,
        kind = kind.suffix(),
        user_id = %ctx.user_id,
        path = %ts_file.display(),
        "scaffolded dev-only entity component"
    );

    Ok((
        StatusCode::CREATED,
        Json(ScaffoldResult {
            files: [ts_file, html_file, css_file]
                .iter()
                .map(|p| display_path(p))
                .collect(),
            registry_updated,
            registry_note,
        }),
    ))
}

// ── Templates ────────────────────────────────────────────────────────────────

fn form_component_ts(
    logicalname: &str,
    url_path: &str,
    class_name: &str,
    selector: &str,
    file_stem: &str,
    form_base_specifier: &str,
) -> String {
    format!(
        r#"import {{ Component }} from '@angular/core';
import {{ ReactiveFormsModule }} from '@angular/forms';
import {{ EngineFormBase }} from '{form_base_specifier}/xrm-form.base';

// Generated by the dev-only Entity Management "Add Form" tool for
// '{logicalname}' (/{url_path}/form?id=…). Starting point only — edit the
// template and styles beside this file, then register any custom behavior here.
//
// EngineFormBase supplies loading()/saving()/error()/schema()/form()/isEdit()/
// id() and save()/cancel(); the template consumes them directly.
@Component({{
  selector: '{selector}',
  standalone: true,
  imports: [ReactiveFormsModule],
  templateUrl: './{file_stem}.component.html',
  // The shared form stylesheet first (it owns every xf-* class the generated
  // template uses), then this component's own file for overrides.
  styleUrls: ['{form_base_specifier}/xrm-form.css', './{file_stem}.component.css'],
}})
export class {class_name} extends EngineFormBase {{
  readonly entityLogicalName = '{logicalname}';
}}
"#
    )
}

const FORM_TEMPLATE_HTML: &str = r#"@if (loading()) {
  <div class="xf-loading">Loading record…</div>
} @else {
  <form [formGroup]="form()" (ngSubmit)="save()" class="xf-page">

    <div class="xf-header">
      <h1 class="xf-title">{{ isEdit() ? 'Edit' : 'New' }} record</h1>
      <div class="xf-actions">
        <button type="button" class="xf-btn xf-btn-secondary" (click)="cancel()">Cancel</button>
        <button type="submit" class="xf-btn xf-btn-primary" [disabled]="saving()">Save</button>
      </div>
    </div>

    <div class="xf-body">
      @if (error()) { <div class="xf-error-banner">{{ error() }}</div> }

      <!-- Replace this generic loop with the sections/layout this entity needs. -->
      @for (f of schema()?.fields ?? []; track f.name) {
        <div class="xf-field">
          <label [for]="f.name">{{ f.display_name }}</label>
          <input [id]="f.name" type="text" [formControlName]="f.name" class="xf-input" />
        </div>
      }
    </div>

  </form>
}
"#;

fn list_component_ts(
    logicalname: &str,
    url_path: &str,
    class_name: &str,
    selector: &str,
    file_stem: &str,
) -> String {
    format!(
        r#"import {{ Component, inject, input }} from '@angular/core';
import {{ Router }} from '@angular/router';
import {{ EntityListComponent, entityFormRoute }} from '@attome/xrm/entity';
import type {{ EntityRecord }} from '@attome/xrm';

// Generated by the dev-only Entity Management "Add List" tool for
// '{logicalname}' (/{url_path}/list). Starting point only: it wraps the stock
// metadata-driven grid — same views, filters, sorting, and paging — and routes
// New/Edit at the ordinary entity form. Re-point those handlers, or replace
// the template entirely, as this entity needs.
//
// `name()` is the entity logicalname the router binds when this override is
// selected; pass it straight through to <attome-metadata-list>.
@Component({{
  selector: '{selector}',
  standalone: true,
  imports: [EntityListComponent],
  templateUrl: './{file_stem}.component.html',
  styleUrls: ['./{file_stem}.component.css'],
}})
export class {class_name} {{
  private readonly router = inject(Router);

  readonly name = input('');

  onCreate(): void {{
    void this.router.navigate(entityFormRoute(this.name()));
  }}

  onEdit(record: EntityRecord): void {{
    void this.router.navigate(entityFormRoute(this.name()), {{
      queryParams: {{ id: record.id }},
    }});
  }}
}}
"#
    )
}

const LIST_TEMPLATE_HTML: &str = r#"<attome-metadata-list
  [entityName]="name()"
  (newClick)="onCreate()"
  (editClick)="onEdit($event)"
/>
"#;

fn component_css(logicalname: &str, kind: ScaffoldKind) -> String {
    let shared = match kind {
        ScaffoldKind::Form => "   Loaded after xrm-form.css, so any xf-* rule written here wins.\n",
        ScaffoldKind::List => {
            "   <attome-metadata-list> brings its own styles; this file is for the\n   wrapper only.\n"
        }
    };
    format!(
        "/* Styles for the '{logicalname}' {} override.\n{shared}*/\n:host {{\n  display: block;\n}}\n",
        kind.suffix(),
    )
}

// ── Registry wiring ──────────────────────────────────────────────────────────

/// Appends one import + one `registry.register(...)` line to
/// `provide-xrm-forms.ts`'s existing `registerForms()` function — the file
/// that already wires every hand-written entity override. A pure text append:
/// never touches `xrm-shell.routes.ts` or any `Routes` array.
/// `EntityRouteRegistry.register` merges its override object into whatever is
/// already there, so a form and a list scaffolded for the same entity compose
/// into one entry without this needing to rewrite the earlier line.
///
/// Returns `(false, Some(reason))` — files still written — when it declines or
/// fails, so the caller can register by hand. Declines outright for a target
/// outside `projects/xrm/forms/`: `provide-xrm-forms.ts` ships inside the
/// `@attome/xrm` library, and a relative import reaching out of that package
/// (into the host app, say) breaks the ng-packagr build rather than producing
/// a working override.
async fn register_component(
    target_dir: &std::path::Path,
    file_stem: &str,
    class_name: &str,
    logicalname: &str,
    kind: ScaffoldKind,
) -> std::io::Result<(bool, Option<String>)> {
    let forms_root = match angular_root().join("projects/xrm/forms").canonicalize() {
        Ok(p) => p,
        Err(e) => return Ok((false, Some(format!("forms/ directory not found: {e}")))),
    };
    if !target_dir.starts_with(&forms_root) {
        return Ok((
            false,
            Some(format!(
                "target is outside {} — a component there cannot be imported by \
                 provide-xrm-forms.ts without breaking the library build, so register it \
                 yourself (or move it under forms/)",
                display_path(&forms_root)
            )),
        ));
    }

    let registry_file = form_dir().join("provide-xrm-forms.ts");
    let registry_dir = match registry_file.parent().map(std::path::Path::canonicalize) {
        Some(Ok(p)) => p,
        _ => return Ok((false, Some("provide-xrm-forms.ts not found".to_owned()))),
    };
    let contents = tokio::fs::read_to_string(&registry_file).await?;

    let specifier = relative_specifier(&registry_dir, &target_dir.join(file_stem));
    let import_line = format!("import {{ {class_name} }} from '{specifier}.component';\n");
    if contents.contains(&import_line) {
        return Ok((true, None)); // already registered, nothing to do
    }

    const ANCHOR: &str = "function registerForms(registry: EntityRouteRegistry): void {\n";
    let Some(anchor_pos) = contents.find(ANCHOR) else {
        return Ok((
            false,
            Some("registerForms() anchor not found in provide-xrm-forms.ts".to_owned()),
        ));
    };
    let register_line = format!(
        "  registry.register('{logicalname}', {{ {}: {class_name} }});\n",
        kind.registry_field()
    );
    let insert_at = anchor_pos + ANCHOR.len();

    let mut next = String::with_capacity(contents.len() + import_line.len() + register_line.len());
    next.push_str(&import_line);
    next.push_str(&contents[..insert_at]);
    next.push_str(&register_line);
    next.push_str(&contents[insert_at..]);

    tokio::fs::write(&registry_file, next).await?;
    Ok((true, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_specifier_walks_up_and_back_down() {
        let from = PathBuf::from("/repo/angular/projects/xrm/forms/xrm-form");
        assert_eq!(
            relative_specifier(
                &from,
                std::path::Path::new("/repo/angular/projects/xrm/forms/invoice/x-form")
            ),
            "../invoice/x-form"
        );
        assert_eq!(
            relative_specifier(
                &from,
                std::path::Path::new("/repo/angular/projects/xrm/forms/xrm-form/y")
            ),
            "./y"
        );
    }

    // The three checks resolve_target_dir exists for. Containment itself needs
    // a real filesystem (canonicalize), so it is covered by the angular/ tree
    // this repo always has; the lexical rejections below need nothing.
    #[test]
    fn resolve_target_dir_rejects_relative_and_parent_traversal() {
        assert!(resolve_target_dir("projects/xrm/forms/x").is_err());
        assert!(resolve_target_dir("").is_err());
        #[cfg(windows)]
        let escaping = r"C:\repo\angular\..\..\Windows\System32";
        #[cfg(not(windows))]
        let escaping = "/repo/angular/../../etc";
        assert!(resolve_target_dir(escaping).is_err());
    }

    #[test]
    fn resolve_target_dir_rejects_an_absolute_path_outside_the_checkout() {
        #[cfg(windows)]
        let outside = r"C:\Windows\Temp";
        #[cfg(not(windows))]
        let outside = "/tmp";
        assert!(resolve_target_dir(outside).is_err());
    }

    #[test]
    fn resolve_target_dir_accepts_a_not_yet_created_dir_inside_angular() {
        let root = canonical_angular_root().expect("angular/ exists in this checkout");
        let target = root.join("projects/xrm/forms/scaffold-test-does-not-exist");
        let resolved =
            resolve_target_dir(&target.to_string_lossy()).expect("inside angular/ is allowed");
        assert!(resolved.starts_with(&root));
        assert!(resolved.ends_with("scaffold-test-does-not-exist"));
    }

    #[test]
    fn class_and_file_names_follow_the_entity_logicalname() {
        assert_eq!(class_prefix("user_account"), "UserAccount");
        assert_eq!(ScaffoldKind::Form.class_suffix(), "FormComponent");
        assert_eq!(ScaffoldKind::List.registry_field(), "listComponent");
    }
}

/// P-api-contract Phase 1 — this file's slice of the workspace OpenAPI document. Separate per file
/// because `#[utoipa::path]` generates a `__path_*` type with the handler's
/// own visibility, and these handlers are module-private — the crate's
/// `openapi()` merges every fragment back into one document.
#[derive(utoipa::OpenApi)]
#[openapi(paths(dev_tools_available, scaffold_form_component))]
struct ApiDocFragment;

pub(crate) fn openapi_fragment() -> utoipa::openapi::OpenApi {
    <ApiDocFragment as utoipa::OpenApi>::openapi()
}
