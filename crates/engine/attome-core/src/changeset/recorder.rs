//! The recorder (design §4.1–§4.3): which changeset a metadata write records
//! into, which layer a new row gets, whether an existing row may be changed,
//! and appending one operation as the last statement before commit.
//!
//! # Transaction boundary
//!
//! [`Recording::record`] runs inside the write's own transaction, after the
//! metadata write and after the D-025 change-log append where the path has
//! one. It takes the changeset row `FOR UPDATE`, checks it is open, inserts
//! the operation with `seq = op_count + 1`, and bumps `op_count`. The
//! changeset row is the last lock any metadata transaction takes, so two
//! writes into the same changeset queue on it and cannot deadlock, and `seq`
//! order equals commit order. No advisory lock is added.
//!
//! # Selecting the changeset (§4.3)
//!
//! 1. `X-Attome-Changeset: <uuid>` names it; it must be open.
//! 2. Otherwise the caller's own open changeset: exactly one is used, more
//!    than one is `changeset_ambiguous`.
//! 3. Otherwise `required` mode refuses (`changeset_required`) and `auto` mode
//!    records into an automatic changeset (`origin` `auto`, or `break_glass`
//!    when a break-glass window admitted the request) that is inserted already
//!    closed in the write's transaction. Every write of one request shares it;
//!    attome-server seals it (document + checksum) later.
//!
//! [`Recording::preflight`] runs 1–3 without writing, so a path that commits
//! DDL before its metadata transaction refuses before the DDL.

use std::sync::{Mutex, PoisonError};

use attome_db::{DbPool, Tx};
use attome_types::AppError;
use sqlx::PgConnection;
use uuid::Uuid;

use super::errors;
use super::model::{ChangesetStatus, Layer, Origin, RecordedOp, RecordingMode};
use super::store::LOG_WATERMARK_SQL;

/// Everything the recorder needs to know about an admin request. Built by
/// the [`super::RecordingCtx`] extractor, or by hand for a deferred write
/// (an approval executed later records into the changeset captured at
/// request time: `header = Some(id)`).
#[derive(Debug, Clone)]
pub struct RequestContext {
    /// `X-Attome-Changeset`, when sent.
    pub header: Option<Uuid>,
    /// The authenticated principal; `None` for a system actor.
    pub actor: Option<Uuid>,
    pub actor_label: String,
    pub request_id: Option<String>,
    /// `"PATCH /api/v1/admin/views/{id}"`.
    pub route: String,
    pub mode: RecordingMode,
    pub auto_layer: Layer,
    /// A break-glass window admitted this request: the layer rule is skipped
    /// and an automatic changeset is recorded with `origin = 'break_glass'`.
    pub break_glass: bool,
}

/// The changeset a request records into, as resolved by
/// [`Recording::preflight`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolved {
    /// `None` until an automatic changeset has been inserted.
    pub changeset_id: Option<Uuid>,
    pub layer: Layer,
    /// `Some` when the writes go to an automatic changeset.
    pub automatic: Option<Origin>,
}

/// A request's recording state.
#[derive(Debug)]
pub struct RequestRecording {
    ctx: RequestContext,
    /// Resolved once per request. A std mutex: it is never held across an
    /// `.await` (every access copies the value out).
    resolved: Mutex<Option<Resolved>>,
}

impl RequestRecording {
    pub fn context(&self) -> &RequestContext {
        &self.ctx
    }

    fn cached(&self) -> Option<Resolved> {
        *self.resolved.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn cache(&self, resolved: Resolved) {
        *self.resolved.lock().unwrap_or_else(PoisonError::into_inner) = Some(resolved);
    }
}

/// How a metadata write is recorded (design §4.1).
#[derive(Debug)]
pub enum Recording {
    /// An admin request: recorded into a changeset.
    Request(RequestRecording),
    /// The changeset applier and the replay tool: rows are stamped `layer`,
    /// nothing is recorded (the apply ledger is the record).
    Applying { layer: Layer },
    /// Boot seeds and platform definitions: rows are stamped `platform`,
    /// nothing is recorded.
    Seed,
}

impl Recording {
    pub fn for_request(ctx: RequestContext) -> Self {
        Self::Request(RequestRecording {
            ctx,
            resolved: Mutex::new(None),
        })
    }

    /// Resolves (and caches) the target changeset before any work, refusing
    /// early: `changeset_not_open`, `changeset_ambiguous`,
    /// `changeset_required`. Writes nothing.
    pub async fn preflight(&self, db: &DbPool) -> Result<Resolved, AppError> {
        match self {
            Self::Request(req) => {
                if let Some(resolved) = req.cached() {
                    return Ok(resolved);
                }
                let mut conn = db.acquire().await.map_err(AppError::internal)?;
                let resolved = resolve(&mut conn, &req.ctx).await?;
                req.cache(resolved);
                Ok(resolved)
            }
            Self::Applying { layer } => Ok(Resolved {
                changeset_id: None,
                layer: *layer,
                automatic: None,
            }),
            Self::Seed => Ok(Resolved {
                changeset_id: None,
                layer: Layer::Platform,
                automatic: None,
            }),
        }
    }

    /// The layer a new row gets. A request must have been preflighted (or
    /// recorded) first: stamping before the changeset is known would guess.
    pub fn stamp(&self) -> Result<Layer, AppError> {
        match self {
            Self::Request(req) => req.cached().map(|r| r.layer).ok_or_else(|| {
                AppError::internal("changeset recording: stamp() before preflight()")
            }),
            Self::Applying { layer } => Ok(*layer),
            Self::Seed => Ok(Layer::Platform),
        }
    }

    /// `409 layer_mismatch` unless a row owned by `row_layer` may be updated,
    /// retired, reactivated or removed by this recording (design §1):
    /// only by its own layer. A break-glass request skips the rule; boot seeds
    /// own the platform definitions and are not checked (every row is
    /// `project` until the boot stamp step has run).
    pub fn check_owner(&self, row_layer: Layer) -> Result<(), AppError> {
        let layer = match self {
            Self::Seed => return Ok(()),
            Self::Applying { layer } => *layer,
            Self::Request(req) => {
                if req.ctx.break_glass {
                    return Ok(());
                }
                self.stamp()?
            }
        };
        if layer == row_layer {
            Ok(())
        } else {
            Err(AppError::Conflict(errors::LAYER_MISMATCH))
        }
    }

    /// Appends one operation to the resolved changeset. MUST be the last
    /// statement before `commit()`, inside the write's transaction. A no-op
    /// for [`Recording::Applying`] and [`Recording::Seed`]. A write that
    /// changed nothing must not call this ("exactly one operation per
    /// change").
    pub async fn record(&self, tx: &mut Tx<'_>, op: RecordedOp) -> Result<(), AppError> {
        let Self::Request(req) = self else {
            return Ok(());
        };
        op.check()
            .map_err(|e| AppError::internal(format!("changeset recording: {e}")))?;

        let mut resolved = match req.cached() {
            Some(r) => r,
            None => {
                let r = resolve(tx, &req.ctx).await?;
                req.cache(r);
                r
            }
        };

        // At most two passes: the second only after replacing an automatic
        // changeset that vanished (its first transaction rolled back) or was
        // already sealed.
        let (changeset_id, op_count) = 'lock: {
            for _ in 0..2 {
                let id = match resolved.changeset_id {
                    Some(id) => id,
                    None => {
                        let origin = resolved.automatic.ok_or_else(|| {
                            AppError::internal("changeset recording: no changeset resolved")
                        })?;
                        let id = insert_automatic(tx, &req.ctx, resolved.layer, origin).await?;
                        resolved.changeset_id = Some(id);
                        req.cache(resolved);
                        id
                    }
                };
                let row: Option<(String, String, String, i32, bool)> = sqlx::query_as(
                    "SELECT layer, status, origin, op_count, document IS NULL \
                     FROM changeset WHERE id = $1 FOR UPDATE",
                )
                .bind(id)
                .fetch_optional(&mut **tx)
                .await
                .map_err(AppError::internal)?;

                let Some((layer, status, origin, op_count, unsealed)) = row else {
                    if resolved.automatic.is_some() {
                        resolved.changeset_id = None;
                        continue;
                    }
                    return Err(AppError::Conflict(errors::CHANGESET_NOT_OPEN));
                };
                if layer != resolved.layer.as_str() {
                    return Err(AppError::internal(format!(
                        "changeset {id}: layer {layer} differs from the resolved {}",
                        resolved.layer.as_str()
                    )));
                }
                let own_automatic = resolved.automatic.is_some()
                    && Origin::parse(&origin).is_some_and(Origin::is_automatic);
                match ChangesetStatus::parse(&status) {
                    Some(ChangesetStatus::Open) => break 'lock (id, op_count),
                    Some(ChangesetStatus::Closed) if own_automatic && unsealed => {
                        break 'lock (id, op_count);
                    }
                    Some(ChangesetStatus::Closed) if own_automatic => {
                        // Sealed between two of this request's writes: the
                        // rest go to a fresh automatic changeset.
                        resolved.changeset_id = None;
                        continue;
                    }
                    _ => return Err(AppError::Conflict(errors::CHANGESET_NOT_OPEN)),
                }
            }
            return Err(AppError::internal(
                "changeset recording: could not settle on an automatic changeset",
            ));
        };

        let seq = op_count
            .checked_add(1)
            .ok_or_else(|| AppError::internal("changeset operation count overflow"))?;
        let changed: Vec<String> = op.changed.iter().map(|s| (*s).to_owned()).collect();
        sqlx::query(
            "INSERT INTO changeset_operation \
                 (changeset_ref, seq, op, phase, object_kind, object_ref, target, snapshot, \
                  changed, route, request_id, actor_ref) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(changeset_id)
        .bind(seq)
        .bind(op.op.as_str())
        .bind(op.op.phase().as_str())
        .bind(op.object_kind)
        .bind(op.object_ref)
        .bind(&op.target)
        .bind(&op.snapshot)
        .bind(&changed)
        .bind(&req.ctx.route)
        .bind(&req.ctx.request_id)
        .bind(req.ctx.actor)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;

        let bumped = sqlx::query(
            "UPDATE changeset \
             SET op_count = $2, updated_at = now(), row_version = row_version + 1 \
             WHERE id = $1 AND op_count = $3",
        )
        .bind(changeset_id)
        .bind(seq)
        .bind(op_count)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
        if bumped.rows_affected() != 1 {
            // Unreachable while the row lock is held; refuse rather than leave
            // op_count and the operations disagreeing.
            return Err(AppError::internal(format!(
                "changeset {changeset_id}: op_count moved under its row lock"
            )));
        }
        Ok(())
    }
}

/// Steps 1–3 of §4.3, reading only.
async fn resolve(conn: &mut PgConnection, ctx: &RequestContext) -> Result<Resolved, AppError> {
    if let Some(id) = ctx.header {
        let row: Option<(String, String)> =
            sqlx::query_as("SELECT layer, status FROM changeset WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await
                .map_err(AppError::internal)?;
        return match row {
            Some((layer, status)) if status == ChangesetStatus::Open.as_str() => Ok(Resolved {
                changeset_id: Some(id),
                layer: parse_layer(&layer)?,
                automatic: None,
            }),
            _ => Err(AppError::Conflict(errors::CHANGESET_NOT_OPEN)),
        };
    }
    if let Some(actor) = ctx.actor {
        let open: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, layer FROM changeset \
             WHERE author_ref = $1 AND status = 'open' ORDER BY opened_at LIMIT 2",
        )
        .bind(actor)
        .fetch_all(&mut *conn)
        .await
        .map_err(AppError::internal)?;
        match open.as_slice() {
            [(id, layer)] => {
                return Ok(Resolved {
                    changeset_id: Some(*id),
                    layer: parse_layer(layer)?,
                    automatic: None,
                });
            }
            [] => {}
            _ => return Err(AppError::Conflict(errors::CHANGESET_AMBIGUOUS)),
        }
    }
    match ctx.mode {
        RecordingMode::Required => Err(AppError::Conflict(errors::CHANGESET_REQUIRED)),
        RecordingMode::Auto => Ok(Resolved {
            changeset_id: None,
            layer: ctx.auto_layer,
            automatic: Some(if ctx.break_glass {
                Origin::BreakGlass
            } else {
                Origin::Auto
            }),
        }),
    }
}

fn parse_layer(layer: &str) -> Result<Layer, AppError> {
    Layer::parse(layer)
        .ok_or_else(|| AppError::internal(format!("unknown changeset layer {layer:?}")))
}

/// `auto-<yyyymmdd-hhmmss>-<8 hex>`: within the table's name CHECK (at most
/// 60 characters, lowercase, `-`-joined).
fn automatic_name(id: Uuid, at: chrono::DateTime<chrono::Utc>) -> String {
    let hex = id.simple().to_string();
    format!(
        "auto-{}-{}",
        at.format("%Y%m%d-%H%M%S"),
        &hex[hex.len() - 8..]
    )
}

/// `Automatic: <route>`, cut to the table's 200-character title limit.
fn automatic_title(route: &str) -> String {
    format!("Automatic: {route}").chars().take(200).collect()
}

/// Inserts an automatic changeset, already closed (its checksum is sealed
/// later by attome-server), in the write's transaction.
async fn insert_automatic(
    tx: &mut Tx<'_>,
    ctx: &RequestContext,
    layer: Layer,
    origin: Origin,
) -> Result<Uuid, AppError> {
    let id = Uuid::now_v7();
    let sql = format!(
        "INSERT INTO changeset \
             (id, layer, scope, name, title, origin, status, closed_at, opened_log_id, \
              author_ref, author_label) \
         VALUES ($1, $2, 'auto', $3, $4, $5, 'closed', now(), {LOG_WATERMARK_SQL}, $6, $7)"
    );
    sqlx::query(&sql)
        .bind(id)
        .bind(layer.as_str())
        .bind(automatic_name(id, chrono::Utc::now()))
        .bind(automatic_title(&ctx.route))
        .bind(origin.as_str())
        .bind(ctx.actor)
        .bind(&ctx.actor_label)
        .execute(&mut **tx)
        .await
        .map_err(AppError::internal)?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::super::store::{is_valid_name, is_valid_scope};
    use super::*;

    fn ctx(mode: RecordingMode, break_glass: bool) -> RequestContext {
        RequestContext {
            header: None,
            actor: Some(Uuid::now_v7()),
            actor_label: "user:test".into(),
            request_id: None,
            route: "POST /api/v1/admin/views".into(),
            mode,
            auto_layer: Layer::Project,
            break_glass,
        }
    }

    #[test]
    fn automatic_names_and_titles_fit_the_table_checks() {
        let name = automatic_name(Uuid::now_v7(), chrono::Utc::now());
        assert!(is_valid_name(&name), "{name}");
        assert!(name.len() <= 60);
        assert!(is_valid_scope("auto"));
        let title = automatic_title(&"x".repeat(500));
        assert_eq!(title.chars().count(), 200);
    }

    #[test]
    fn stamp_and_check_owner_need_a_resolved_request() {
        let recording = Recording::for_request(ctx(RecordingMode::Required, false));
        assert!(matches!(recording.stamp(), Err(AppError::Internal(_))));
        assert!(matches!(
            recording.check_owner(Layer::Project),
            Err(AppError::Internal(_))
        ));

        let Recording::Request(req) = &recording else {
            unreachable!()
        };
        req.cache(Resolved {
            changeset_id: Some(Uuid::now_v7()),
            layer: Layer::Project,
            automatic: None,
        });
        assert_eq!(recording.stamp().ok(), Some(Layer::Project));
        assert!(recording.check_owner(Layer::Project).is_ok());
        let Err(AppError::Conflict(message)) = recording.check_owner(Layer::Platform) else {
            panic!("a platform row must be refused to a project changeset");
        };
        assert_eq!(errors::code_of(message), "layer_mismatch");
    }

    #[test]
    fn break_glass_skips_the_layer_rule() {
        let recording = Recording::for_request(ctx(RecordingMode::Auto, true));
        assert!(recording.check_owner(Layer::Platform).is_ok());
    }

    #[test]
    fn applying_and_seed_stamp_without_a_changeset() {
        let applying = Recording::Applying {
            layer: Layer::Product,
        };
        assert_eq!(applying.stamp().ok(), Some(Layer::Product));
        assert!(applying.check_owner(Layer::Product).is_ok());
        assert!(applying.check_owner(Layer::Platform).is_err());

        assert_eq!(Recording::Seed.stamp().ok(), Some(Layer::Platform));
        assert!(Recording::Seed.check_owner(Layer::Project).is_ok());
    }
}
