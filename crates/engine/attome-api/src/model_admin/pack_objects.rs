//! G12-T1 (V2-D1195): packs ship model objects.
//!
//! A pack may carry `packs/<name>/model/**/*.json`, files in the
//! `attome model export` shape (Y1-T10). Boot installs them after the pack's
//! changesets: every object is saved and published on the pack's layer
//! (`app` = the pack's name, owner layer `product`), through the same reads
//! and checks as a blueprint (N12-T3), and `pack_model_object` records the
//! content the pack last published.
//!
//! An upgrade replaces only what the pack still owns. An object whose
//! published content is no longer what the pack last published, or that has
//! an open draft, was changed by the customer: the customer's version is kept
//! and the row says so (`kept_customer`). An object a newer pack no longer
//! ships stays as it is (`removed_from_pack`), for an administrator to retire
//! once nothing uses it. `GET /api/v1/admin/model/pack-objects` lists the rows.

use attome_core::EngineState;
use attome_model::store::{self, ObjectSpec};
use attome_model::{Layer, ObjectId};
use attome_server::authz::{Authorized, Privilege, area};
use attome_types::{AppError, ErrorResponse, OnePageQuery, PageWindow, PaginatedResponse};
use axum::{
    Json,
    extract::{Query, State},
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use super::{BlueprintObject, ModelFile, ModelFiles, kinds, read_blueprint, refresh_cooked};

/// Every model file of the pack `name` (`<packs_root>/<name>/model/**`), as
/// paths relative to `model/` with `/` separators, in path order; none when
/// the pack has no `model/` directory. Blocking file I/O: call it at boot or
/// from `spawn_blocking`.
pub fn read_pack_model_files(
    config: &attome_config::AppConfig,
    name: &str,
) -> Result<Vec<(String, String)>, String> {
    let pack_dir = crate::changeset::boot::packs_root(config).join(name);
    read_model_dir(&pack_dir, name)
}

/// The model files under `<pack_dir>/model/`, as [`read_pack_model_files`]
/// returns them; `name` is only for the error text.
pub fn read_model_dir(
    pack_dir: &std::path::Path,
    name: &str,
) -> Result<Vec<(String, String)>, String> {
    let root = pack_dir.join("model");
    if !root.is_dir() {
        return Ok(Vec::new());
    }
    let mut found = Vec::new();
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|e| format!("pack {name}: cannot read {}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "json") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
        .iter()
        .map(|file| {
            let text = std::fs::read_to_string(file)
                .map_err(|e| format!("pack {name}: cannot read {}: {e}", file.display()))?;
            let relative = file
                .strip_prefix(&root)
                .unwrap_or(file)
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            Ok((relative, text))
        })
        .collect()
}

/// What installing one pack's model objects did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PackModelOutcome {
    /// Objects published, new or replaced.
    pub published: usize,
    /// Objects already as the pack ships them.
    pub unchanged: usize,
    /// Objects the customer changed, kept as the customer left them.
    pub kept_customer: Vec<String>,
    /// Objects an earlier version of the pack shipped and this one does not.
    pub removed_from_pack: Vec<String>,
}

/// The ledger row of one pack object.
#[derive(sqlx::FromRow)]
struct LedgerRow {
    kind: String,
    name: String,
    content_hash: String,
    status: String,
}

/// Installs the pack `pack`'s model `files` (see the module docs). The files
/// are all read and checked before anything is saved, every object must
/// belong to the pack (`app` = `pack`), and the saves and publishes run in
/// one transaction, so a pack's objects land whole or not at all.
pub async fn install_pack_model(
    state: &EngineState,
    pack: &str,
    files: Vec<(String, String)>,
) -> Result<PackModelOutcome, AppError> {
    let request = ModelFiles {
        files: files
            .into_iter()
            .map(|(path, text)| ModelFile { path, text })
            .collect(),
    };
    let objects = read_blueprint(&request)?;
    if let Some(stranger) = objects.iter().find(|o| o.object.app != pack) {
        return Err(AppError::Validation(format!(
            "pack {pack}: {} belongs to app `{}`; a pack ships only its own objects",
            stranger.path, stranger.object.app
        )));
    }

    let db = &state.base.db;
    let ledger: Vec<LedgerRow> = sqlx::query_as(
        "SELECT kind, name, content_hash, status FROM pack_model_object WHERE pack = $1",
    )
    .bind(pack)
    .fetch_all(db)
    .await
    .map_err(AppError::internal)?;
    let last_hash = |kind: &str, name: &str| {
        ledger
            .iter()
            .find(|row| row.kind == kind && row.name == name)
            .map(|row| row.content_hash.clone())
    };

    let mut outcome = PackModelOutcome::default();
    let mut tx = attome_db::tx::begin(db).await?;
    let mut to_publish: Vec<(&BlueprintObject, Uuid, String)> = Vec::new();
    for item in &objects {
        let BlueprintObject { kind, object, .. } = item;
        let kind_name = kind.name().as_str();
        let hash =
            attome_model::canonical::content_hash(&object.doc).map_err(AppError::Validation)?;
        let existing = store::published_state(db, kind_name, pack, &object.name).await?;
        let label = format!("{kind_name}/{}", object.name);
        let Some(existing) = existing else {
            let id = Uuid::now_v7();
            save(&mut tx, item, id).await?;
            to_publish.push((item, id, hash));
            continue;
        };
        let published_hash = existing.published.as_ref().map(|(_, h)| h.clone());
        if published_hash.as_deref() == Some(hash.as_str())
            && !has_draft(&mut tx, existing.id).await?
        {
            record(
                &mut tx,
                pack,
                kind_name,
                &object.name,
                existing.id,
                &hash,
                "installed",
                None,
            )
            .await?;
            outcome.unchanged += 1;
            continue;
        }
        // The pack still owns the object when what is published is what the
        // pack last published and nobody has a draft open on it.
        let owned = published_hash.is_some()
            && published_hash == last_hash(kind_name, &object.name)
            && !has_draft(&mut tx, existing.id).await?;
        if owned {
            save(&mut tx, item, existing.id).await?;
            to_publish.push((item, existing.id, hash));
        } else {
            let previous = last_hash(kind_name, &object.name).unwrap_or_else(|| hash.clone());
            record(
                &mut tx,
                pack,
                kind_name,
                &object.name,
                existing.id,
                &previous,
                "kept_customer",
                Some("the customer changed this object; the pack's new version was not applied"),
            )
            .await?;
            outcome.kept_customer.push(label);
        }
    }
    // Every draft first, then every publish, so objects of one pack may
    // reference each other in any file order.
    for (item, id, hash) in &to_publish {
        attome_model::publish::publish(
            &mut tx,
            kinds(),
            &attome_model::validate::CrossChecks::default(),
            item.kind.as_ref(),
            *id,
        )
        .await?;
        record(
            &mut tx,
            pack,
            item.kind.name().as_str(),
            &item.object.name,
            *id,
            hash,
            "installed",
            None,
        )
        .await?;
    }
    outcome.published = to_publish.len();

    for row in &ledger {
        let shipped = objects
            .iter()
            .any(|o| o.kind.name().as_str() == row.kind && o.object.name == row.name);
        if shipped || row.status == "removed_from_pack" {
            continue;
        }
        sqlx::query(
            "UPDATE pack_model_object SET status = 'removed_from_pack', \
                 detail = 'this version of the pack no longer ships it; retire it once nothing uses it', \
                 updated_at = now() \
             WHERE pack = $1 AND kind = $2 AND name = $3",
        )
        .bind(pack)
        .bind(&row.kind)
        .bind(&row.name)
        .execute(&mut *tx)
        .await
        .map_err(AppError::internal)?;
        outcome
            .removed_from_pack
            .push(format!("{}/{}", row.kind, row.name));
    }
    attome_db::tx::commit(tx).await?;
    if outcome.published > 0 {
        refresh_cooked(state).await?;
    }
    Ok(outcome)
}

/// Saves `item` as the draft of object `id` on the pack's layer. No person
/// authored it, so the version has no `created_by`.
async fn save(
    tx: &mut attome_db::Tx<'_>,
    item: &BlueprintObject,
    id: Uuid,
) -> Result<(), AppError> {
    let spec = ObjectSpec {
        id: ObjectId(id),
        name: item.object.name.clone(),
        app: item.object.app.clone(),
        layer: Layer::App,
    };
    store::save_draft(
        tx,
        kinds(),
        item.kind.as_ref(),
        &spec,
        &item.object.doc,
        None,
    )
    .await?;
    Ok(())
}

async fn has_draft(tx: &mut attome_db::Tx<'_>, id: Uuid) -> Result<bool, AppError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM metadata_object_version \
                         WHERE object_id = $1 AND state = 'draft')",
    )
    .bind(id)
    .fetch_one(&mut **tx)
    .await
    .map_err(AppError::internal)
}

#[allow(clippy::too_many_arguments)]
async fn record(
    tx: &mut attome_db::Tx<'_>,
    pack: &str,
    kind: &str,
    name: &str,
    object_id: Uuid,
    content_hash: &str,
    status: &str,
    detail: Option<&str>,
) -> Result<(), AppError> {
    sqlx::query(
        "INSERT INTO pack_model_object (pack, kind, name, object_id, content_hash, status, detail) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (pack, kind, name) DO UPDATE \
            SET object_id = EXCLUDED.object_id, content_hash = EXCLUDED.content_hash, \
                status = EXCLUDED.status, detail = EXCLUDED.detail, updated_at = now()",
    )
    .bind(pack)
    .bind(kind)
    .bind(name)
    .bind(object_id)
    .bind(content_hash)
    .bind(status)
    .bind(detail)
    .execute(&mut **tx)
    .await
    .map_err(AppError::internal)?;
    Ok(())
}

/// One model object an installed pack shipped.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub(crate) struct PackObjectRow {
    pack: String,
    kind: String,
    name: String,
    object_id: Uuid,
    /// `installed`, `kept_customer` (the customer changed it, so an upgrade
    /// left the customer's version) or `removed_from_pack` (a newer pack no
    /// longer ships it).
    status: String,
    detail: Option<String>,
    updated_at: DateTime<Utc>,
}

/// List pack model objects
///
/// The model objects installed packs shipped, with what the last upgrade
/// did to each (G12-T1): the ones it could not replace because the customer
/// changed them, and the ones a newer pack no longer ships, sort first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/model/pack-objects",
    tag = "admin",
    params(OnePageQuery),
    responses(
        (status = 200, description = "A page of pack objects", body = PaginatedResponse<PackObjectRow>),
        (status = 401, description = "Missing or invalid credentials", body = ErrorResponse),
        (status = 403, description = "Caller lacks the required privilege", body = ErrorResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub(crate) async fn list_pack_objects(
    State(state): State<EngineState>,
    _ctx: Authorized<Privilege<area::DataModel>>,
    Query(paging): Query<OnePageQuery>,
) -> Result<Json<PaginatedResponse<PackObjectRow>>, AppError> {
    let PageWindow {
        page,
        page_size,
        offset,
    } = paging.window();
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM pack_model_object")
        .fetch_one(&state.base.db)
        .await
        .map_err(AppError::internal)?;
    let items: Vec<PackObjectRow> = sqlx::query_as(
        "SELECT pack, kind, name, object_id, status, detail, updated_at FROM pack_model_object \
         ORDER BY status = 'installed', pack, kind, name \
         LIMIT $1 OFFSET $2",
    )
    .bind(page_size)
    .bind(offset)
    .fetch_all(&state.base.db)
    .await
    .map_err(AppError::internal)?;
    Ok(Json(PaginatedResponse::new(items, total, page, page_size)))
}
